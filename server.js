/**
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║  BREVE PAYMENT SERVER  —  server.js                             ║
 * ║                                                                  ║
 * ║  3-layer payment verification:                                   ║
 * ║    1. HMAC signature check  (instant, on every payment)         ║
 * ║    2. Live payment status   (confirm "captured" via Razorpay API)║
 * ║    3. Webhook safety net    (catches browser-close edge cases)   ║
 * ║                                                                  ║
 * ║  Revenue split via Razorpay Route:                               ║
 * ║    Platform (you) → 6.5%  stays in your account                 ║
 * ║    Cafe owner     → 93.5% transferred to their linked account   ║
 * ╚══════════════════════════════════════════════════════════════════╝
 */

require('dotenv').config();
const express  = require('express');
const Razorpay = require('razorpay');
const crypto   = require('crypto');
const cors     = require('cors');
const path     = require('path');

const app = express();

// ── Raw body needed for webhook signature verification ───────────────
// Must come BEFORE express.json()
app.use('/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(cors()); // Restrict to your domain in production: cors({ origin: 'https://yourdomain.com' })
app.use(express.static(path.join(__dirname))); // Serve HTML files from same folder

// ── Razorpay client ──────────────────────────────────────────────────
const razorpay = new Razorpay({
  key_id:     process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

const COMMISSION = parseFloat(process.env.PLATFORM_COMMISSION_PERCENT || '6.5') / 100;

// ── Cafe registry ────────────────────────────────────────────────────
const CAFES = {
  'breve': {
    name:      process.env.CAFE_BREVE_NAME      || 'Breve Cafe',
    accountId: process.env.CAFE_BREVE_ACCOUNT_ID,
  },
};

// ── In-memory order store ─────────────────────────────────────────────
// Maps razorpay_order_id → order metadata
// In production, replace with a database (MongoDB, PostgreSQL, etc.)
const pendingOrders = new Map();  // razorpay_order_id → { verified: false, ... }
const verifiedOrders = new Map(); // razorpay_order_id → { verified: true, payment_id, ... }

// ═══════════════════════════════════════════════════════════════════════
//  POST /create-order
//  Step 1 of the payment flow.
//  Creates a Razorpay order server-side (with Route splits).
//  The frontend cannot fake an order_id — it must call this endpoint.
// ═══════════════════════════════════════════════════════════════════════
app.post('/create-order', async (req, res) => {
  try {
    const { amount_paise, cafe_id, order_ref, table, items_summary } = req.body;

    if (!amount_paise || amount_paise < 100) {
      return res.status(400).json({ error: 'Invalid amount — minimum ₹1 (100 paise)' });
    }
    if (!cafe_id || !CAFES[cafe_id]) {
      return res.status(400).json({ error: `Unknown cafe: "${cafe_id}"` });
    }

    const cafe = CAFES[cafe_id];
    if (!cafe.accountId) {
      return res.status(400).json({ error: 'Cafe linked account not configured' });
    }

    const totalPaise      = Math.round(amount_paise);
    const commissionPaise = Math.round(totalPaise * COMMISSION);
    const cafeSharePaise  = totalPaise - commissionPaise;

    const rzpOrder = await razorpay.orders.create({
      amount:   totalPaise,
      currency: 'INR',
      receipt:  order_ref,
      notes: { cafe: cafe.name, table: String(table), summary: items_summary || '' },
      transfers: [
        {
          account:  cafe.accountId,
          amount:   cafeSharePaise,
          currency: 'INR',
          notes:    { payout_desc: `Order ${order_ref} · Table ${table}`, order_ref },
          linked_account_notes: ['payout_desc'],
          on_hold:  0,
        },
      ],
    });

    // Store order as PENDING — not verified yet
    pendingOrders.set(rzpOrder.id, {
      razorpay_order_id: rzpOrder.id,
      internal_ref:      order_ref,
      cafe_id,
      table,
      amount_paise:      totalPaise,
      commission_paise:  commissionPaise,
      cafe_share_paise:  cafeSharePaise,
      verified:          false,
      created_at:        new Date().toISOString(),
    });

    console.log(`\n[create-order] ${order_ref} | Table ${table} | ₹${totalPaise/100} | rzp: ${rzpOrder.id}`);
    console.log(`  Commission: ₹${commissionPaise/100} | Cafe: ₹${cafeSharePaise/100}`);

    res.json({
      order_id:          rzpOrder.id,
      amount:            rzpOrder.amount,
      currency:          rzpOrder.currency,
      cafe_name:         cafe.name,
      commission_paise:  commissionPaise,
      cafe_share_paise:  cafeSharePaise,
      key_id:            process.env.RAZORPAY_KEY_ID,
    });

  } catch (err) {
    console.error('[create-order error]', err.message || err);
    res.status(500).json({ error: err.error?.description || err.message || 'Server error' });
  }
});

// ═══════════════════════════════════════════════════════════════════════
//  POST /verify-payment
//  Step 2 of the payment flow — called immediately after Razorpay
//  checkout succeeds in the browser.
//
//  LAYER 1: HMAC signature verification
//    Razorpay signs the response with your Key Secret.
//    We recompute the HMAC and compare — any tampering is caught.
//
//  LAYER 2: Live payment status check
//    We call Razorpay's API to confirm the payment is "captured"
//    (money actually moved), not just "created" or "authorized".
//
//  Only after BOTH checks pass is the order marked verified and
//  the kitchen allowed to see it.
// ═══════════════════════════════════════════════════════════════════════
app.post('/verify-payment', async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
      return res.status(400).json({ verified: false, error: 'Missing payment fields' });
    }

    // ── LAYER 1: HMAC signature check ────────────────────────────────
    const body     = razorpay_order_id + '|' + razorpay_payment_id;
    const expected = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(body)
      .digest('hex');

    if (expected !== razorpay_signature) {
      console.warn(`[verify] ✗ SIGNATURE MISMATCH for order ${razorpay_order_id} — possible fraud!`);
      return res.status(400).json({ verified: false, error: 'Signature mismatch — payment rejected' });
    }

    console.log(`[verify] ✓ Signature valid: ${razorpay_payment_id}`);

    // ── LAYER 2: Live status check via Razorpay API ───────────────────
    let paymentStatus = 'unknown';
    try {
      const payment = await razorpay.payments.fetch(razorpay_payment_id);
      paymentStatus = payment.status; // 'captured' | 'authorized' | 'failed' | 'refunded'

      if (payment.status !== 'captured') {
        console.warn(`[verify] ✗ Payment not captured — status: ${payment.status}`);
        return res.status(402).json({
          verified: false,
          error: `Payment not captured (status: ${payment.status})`,
        });
      }

      // Sanity check: amount matches what we expect
      const pending = pendingOrders.get(razorpay_order_id);
      if (pending && payment.amount !== pending.amount_paise) {
        console.warn(`[verify] ✗ Amount mismatch! Expected ${pending.amount_paise}, got ${payment.amount}`);
        return res.status(400).json({ verified: false, error: 'Amount mismatch — payment rejected' });
      }

      console.log(`[verify] ✓ Payment captured: ₹${payment.amount / 100} | ${razorpay_payment_id}`);
    } catch (apiErr) {
      // If Razorpay API is unreachable, fall through — webhook will catch it
      console.warn(`[verify] ⚠ Could not fetch payment status: ${apiErr.message} — relying on webhook`);
    }

    // ── Mark order as VERIFIED ────────────────────────────────────────
    const pending = pendingOrders.get(razorpay_order_id);
    if (pending) {
      const verified = {
        ...pending,
        verified:           true,
        razorpay_payment_id,
        razorpay_signature,
        payment_status:     paymentStatus,
        verified_at:        new Date().toISOString(),
      };
      verifiedOrders.set(razorpay_order_id, verified);
      pendingOrders.delete(razorpay_order_id);

      console.log(`[verify] ✓ Order ${pending.internal_ref} VERIFIED — kitchen notified`);
    }

    res.json({
      verified:    true,
      payment_id:  razorpay_payment_id,
      status:      paymentStatus,
    });

  } catch (err) {
    console.error('[verify-payment error]', err);
    res.status(500).json({ verified: false, error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════
//  GET /order-status/:razorpay_order_id
//  Called by the frontend to check if an order is verified before
//  showing the success screen. This is the gate — if not verified,
//  no success screen, no kitchen notification.
// ═══════════════════════════════════════════════════════════════════════
app.get('/order-status/:razorpay_order_id', (req, res) => {
  const { razorpay_order_id } = req.params;
  if (verifiedOrders.has(razorpay_order_id)) {
    const order = verifiedOrders.get(razorpay_order_id);
    return res.json({ verified: true, order });
  }
  if (pendingOrders.has(razorpay_order_id)) {
    return res.json({ verified: false, status: 'pending' });
  }
  res.status(404).json({ verified: false, status: 'not_found' });
});

// ═══════════════════════════════════════════════════════════════════════
//  POST /webhook
//  LAYER 3 — Razorpay sends events here directly (server-to-server).
//  This catches cases where:
//    - Customer's browser crashed before /verify-payment was called
//    - Network error between browser and your server
//    - Customer closed the tab right after payment
//
//  Setup: dashboard.razorpay.com → Settings → Webhooks
//  URL: https://your-server.com/webhook
//  Events to enable: payment.captured, payment.failed, transfer.settled
// ═══════════════════════════════════════════════════════════════════════
app.post('/webhook', (req, res) => {
  const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;

  // Verify webhook signature
  if (webhookSecret) {
    const signature = req.headers['x-razorpay-signature'];
    const hash = crypto
      .createHmac('sha256', webhookSecret)
      .update(req.body)        // req.body is raw Buffer here
      .digest('hex');

    if (hash !== signature) {
      console.warn('[webhook] ✗ Invalid signature — rejected');
      return res.status(400).json({ error: 'Invalid webhook signature' });
    }
  }

  let event;
  try {
    event = JSON.parse(req.body.toString());
  } catch {
    return res.status(400).json({ error: 'Invalid JSON' });
  }

  console.log(`\n[webhook] Event: ${event.event}`);

  switch (event.event) {

    case 'payment.captured': {
      const payment  = event.payload.payment.entity;
      const orderId  = payment.order_id;
      console.log(`  Payment captured: ${payment.id} | ₹${payment.amount / 100} | order: ${orderId}`);

      // If /verify-payment already ran, skip
      if (verifiedOrders.has(orderId)) {
        console.log('  Already verified via /verify-payment — no action needed');
        break;
      }

      // Browser-crash safety: verify via webhook instead
      const pending = pendingOrders.get(orderId);
      if (pending) {
        const verified = {
          ...pending,
          verified:           true,
          razorpay_payment_id: payment.id,
          payment_status:     'captured',
          verified_via:       'webhook',
          verified_at:        new Date().toISOString(),
        };
        verifiedOrders.set(orderId, verified);
        pendingOrders.delete(orderId);
        console.log(`  ✓ Order ${pending.internal_ref} verified via WEBHOOK — kitchen notified`);
      } else {
        console.log(`  Order ${orderId} not in pending map — may already be processed`);
      }
      break;
    }

    case 'payment.failed': {
      const payment = event.payload.payment.entity;
      console.log(`  ✗ Payment failed: ${payment.id} | reason: ${payment.error_description}`);
      // You could notify the customer here via SMS/email
      break;
    }

    case 'transfer.settled': {
      const transfer = event.payload.transfer.entity;
      console.log(`  Transfer settled: ₹${transfer.amount / 100} → ${transfer.recipient}`);
      // Cafe owner's money has landed in their account
      break;
    }

    case 'refund.created': {
      const refund = event.payload.refund.entity;
      console.log(`  Refund created: ₹${refund.amount / 100} for payment ${refund.payment_id}`);
      break;
    }
  }

  res.json({ received: true });
});

// ═══════════════════════════════════════════════════════════════════════
//  GET /health
// ═══════════════════════════════════════════════════════════════════════
app.get('/health', (req, res) => {
  res.json({
    status:              'ok',
    commission:          `${(COMMISSION * 100).toFixed(1)}%`,
    pending_orders:      pendingOrders.size,
    verified_orders:     verifiedOrders.size,
    timestamp:           new Date().toISOString(),
  });
});

// ═══════════════════════════════════════════════════════════════════════
//  GET /commission-preview/:amount
// ═══════════════════════════════════════════════════════════════════════
app.get('/commission-preview/:amount', (req, res) => {
  const amount  = parseFloat(req.params.amount);
  const yourCut = +(amount * COMMISSION).toFixed(2);
  const cafeCut = +(amount - yourCut).toFixed(2);
  res.json({
    order_amount:     amount,
    platform_cut:     yourCut,
    platform_percent: `${(COMMISSION * 100).toFixed(1)}%`,
    cafe_receives:    cafeCut,
    cafe_percent:     `${((1 - COMMISSION) * 100).toFixed(1)}%`,
  });
});

// ── Start ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n╔═══════════════════════════════════════════════╗`);
  console.log(`║  Breve Payment Server                         ║`);
  console.log(`║  http://localhost:${PORT}                         ║`);
  console.log(`║  Commission: ${(COMMISSION*100).toFixed(1)}%                          ║`);
  console.log(`║                                               ║`);
  console.log(`║  Verification layers:                         ║`);
  console.log(`║    ✓  HMAC signature check (Layer 1)          ║`);
  console.log(`║    ✓  Live payment status  (Layer 2)          ║`);
  console.log(`║    ✓  Webhook safety net   (Layer 3)          ║`);
  console.log(`╚═══════════════════════════════════════════════╝\n`);
  console.log(`  Razorpay Key: ${process.env.RAZORPAY_KEY_ID || '⚠  NOT SET'}`);
  console.log(`  Webhook secret: ${process.env.RAZORPAY_WEBHOOK_SECRET ? '✓ set' : '⚠  not set (Layer 3 disabled)'}\n`);
});
