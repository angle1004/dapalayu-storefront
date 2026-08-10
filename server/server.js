import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const { MONGODB_URI, JWT_SECRET, CLIENT_ORIGIN = '', PORT = 10000, ADMIN_EMAILS = '' } = process.env;
if (!MONGODB_URI || !JWT_SECRET) throw new Error('MONGODB_URI와 JWT_SECRET 환경변수가 필요합니다.');

const app = express();
const origins = CLIENT_ORIGIN.split(',').map(x => x.trim()).filter(Boolean);
app.use(cors({ origin(origin, done) {
  if (!origin || origins.includes(origin)) return done(null, true);
  return done(new Error('허용되지 않은 Origin입니다.'));
}, credentials: true }));
app.use(express.json({ limit: '1mb' }));

const addressSchema = new mongoose.Schema({
  recipient: { type: String, required: true, trim: true },
  phone: { type: String, required: true, trim: true },
  zip: { type: String, trim: true }, street: { type: String, required: true, trim: true },
  ward: { type: String, trim: true }, district: { type: String, trim: true }, province: { type: String, trim: true }
}, { _id: false });
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 80 },
  email: { type: String, required: true, trim: true, lowercase: true, unique: true, index: true },
  phone: { type: String, trim: true }, passwordHash: { type: String, required: true },
  role: { type: String, enum: ['customer', 'admin'], default: 'customer' }, addresses: [addressSchema]
}, { timestamps: true });
const orderSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  orderNo: { type: String, required: true, unique: true, index: true },
  items: [{ productId: Number, name: String, option: String, quantity: Number, unitPrice: Number }],
  subtotal: Number, shippingFee: Number, total: { type: Number, required: true }, shippingAddress: addressSchema,
  status: { type: String, enum: ['paid', 'preparing', 'shipped', 'delivered', 'cancelled'], default: 'paid', index: true }
}, { timestamps: true });
const messageSchema = new mongoose.Schema({ from: { type: String, enum: ['customer', 'admin'], required: true }, body: { type: String, required: true, maxlength: 2000 } }, { timestamps: true, _id: true });
const threadSchema = new mongoose.Schema({ customer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true }, messages: [messageSchema], lastMessageAt: { type: Date, default: Date.now } }, { timestamps: true });
const User = mongoose.model('User', userSchema);
const Order = mongoose.model('Order', orderSchema);
const Thread = mongoose.model('Thread', threadSchema);

const publicUser = user => ({ id: user._id, name: user.name, email: user.email, phone: user.phone, role: user.role, addresses: user.addresses, createdAt: user.createdAt });
const tokenFor = user => jwt.sign({ sub: user._id.toString(), role: user.role }, JWT_SECRET, { expiresIn: '7d' });
const adminEmails = new Set(ADMIN_EMAILS.split(',').map(x => x.trim().toLowerCase()).filter(Boolean));
function auth(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: '로그인이 필요합니다.' });
  try { req.auth = jwt.verify(token, JWT_SECRET); next(); } catch { res.status(401).json({ error: '세션이 만료되었습니다.' }); }
}
function adminOnly(req, res, next) { return req.auth?.role === 'admin' ? next() : res.status(403).json({ error: '관리자 권한이 필요합니다.' }); }
function orderNo() { return `DP-${new Date().toISOString().slice(2,10).replaceAll('-','')}-${Math.random().toString().slice(2,8)}`; }

app.get('/health', (_, res) => res.json({ ok: true }));
app.post('/api/auth/signup', async (req, res, next) => {
  try {
    const { name, email, phone = '', password } = req.body;
    if (!name || !email || !password || password.length < 8) return res.status(400).json({ error: '이름, 이메일, 8자 이상 비밀번호가 필요합니다.' });
    const normalized = email.trim().toLowerCase();
    if (await User.exists({ email: normalized })) return res.status(409).json({ error: '이미 가입된 이메일입니다.' });
    const user = await User.create({ name, email: normalized, phone, passwordHash: await bcrypt.hash(password, 12), role: adminEmails.has(normalized) ? 'admin' : 'customer' });
    res.status(201).json({ token: tokenFor(user), user: publicUser(user) });
  } catch (error) { next(error); }
});
app.post('/api/auth/login', async (req, res, next) => {
  try {
    const user = await User.findOne({ email: String(req.body.email || '').trim().toLowerCase() });
    if (!user || !(await bcrypt.compare(req.body.password || '', user.passwordHash))) return res.status(401).json({ error: '이메일 또는 비밀번호가 올바르지 않습니다.' });
    if (adminEmails.has(user.email) && user.role !== 'admin') { user.role = 'admin'; await user.save(); }
    res.json({ token: tokenFor(user), user: publicUser(user) });
  } catch (error) { next(error); }
});
app.get('/api/me', auth, async (req, res, next) => { try { const user = await User.findById(req.auth.sub); if (!user) return res.status(404).json({ error: '회원을 찾을 수 없습니다.' }); res.json({ user: publicUser(user) }); } catch (error) { next(error); } });

app.post('/api/orders', auth, async (req, res, next) => {
  try {
    const { items, subtotal = 0, shippingFee = 0, total, shippingAddress } = req.body;
    if (!Array.isArray(items) || !items.length || !Number.isFinite(total) || !shippingAddress?.recipient || !shippingAddress?.street) return res.status(400).json({ error: '주문 정보가 충분하지 않습니다.' });
    const order = await Order.create({ user: req.auth.sub, orderNo: orderNo(), items, subtotal, shippingFee, total, shippingAddress });
    res.status(201).json({ order });
  } catch (error) { next(error); }
});
app.get('/api/orders', auth, async (req, res, next) => { try { const filter = req.auth.role === 'admin' ? {} : { user: req.auth.sub }; res.json({ orders: await Order.find(filter).populate('user', 'name email phone').sort({ createdAt: -1 }) }); } catch (error) { next(error); } });
app.patch('/api/orders/:id/status', auth, adminOnly, async (req, res, next) => {
  try {
    const statuses = ['paid', 'preparing', 'shipped', 'delivered', 'cancelled'];
    if (!statuses.includes(req.body.status)) return res.status(400).json({ error: '유효하지 않은 주문 상태입니다.' });
    const order = await Order.findByIdAndUpdate(req.params.id, { status: req.body.status }, { new: true });
    if (!order) return res.status(404).json({ error: '주문을 찾을 수 없습니다.' });
    res.json({ order });
  } catch (error) { next(error); }
});

app.get('/api/admin/dashboard', auth, adminOnly, async (_, res, next) => {
  try {
    const [revenue] = await Order.aggregate([{ $match: { status: { $ne: 'cancelled' } } }, { $group: { _id: null, total: { $sum: '$total' }, count: { $sum: 1 } } }]);
    const [users, pending, recentOrders] = await Promise.all([User.countDocuments(), Order.countDocuments({ status: { $in: ['paid', 'preparing'] } }), Order.find().populate('user', 'name email').sort({ createdAt: -1 }).limit(10)]);
    res.json({ revenue: revenue?.total || 0, orderCount: revenue?.count || 0, userCount: users, pendingCount: pending, recentOrders });
  } catch (error) { next(error); }
});
app.get('/api/admin/users', auth, adminOnly, async (_, res, next) => { try { res.json({ users: await User.find().select('-passwordHash').sort({ createdAt: -1 }) }); } catch (error) { next(error); } });

app.get('/api/chat/threads', auth, async (req, res, next) => {
  try { const filter = req.auth.role === 'admin' ? {} : { customer: req.auth.sub }; res.json({ threads: await Thread.find(filter).populate('customer', 'name email').sort({ lastMessageAt: -1 }) }); } catch (error) { next(error); }
});
app.post('/api/chat/threads/:customerId/messages', auth, async (req, res, next) => {
  try {
    const customerId = req.auth.role === 'admin' ? req.params.customerId : req.auth.sub;
    if (req.auth.role !== 'admin' && customerId !== req.auth.sub) return res.status(403).json({ error: '권한이 없습니다.' });
    const body = String(req.body.body || '').trim(); if (!body) return res.status(400).json({ error: '메시지를 입력하세요.' });
    const thread = await Thread.findOneAndUpdate({ customer: customerId }, { $push: { messages: { from: req.auth.role === 'admin' ? 'admin' : 'customer', body } }, $set: { lastMessageAt: new Date() } }, { new: true, upsert: true }).populate('customer', 'name email');
    res.status(201).json({ thread });
  } catch (error) { next(error); }
});
app.use((error, _, res, __) => { console.error(error); res.status(500).json({ error: '서버 오류가 발생했습니다.' }); });

mongoose.connect(MONGODB_URI).then(() => app.listen(PORT, () => console.log(`API listening on ${PORT}`))).catch(error => { console.error('MongoDB 연결 실패', error); process.exit(1); });
