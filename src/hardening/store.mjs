export function createStore() {
  const users = new Map();
  const orders = new Map();
  const webhookEvents = new Set();
  const setupTokens = new Map();
  const inquiries = [];
  const subscribers = new Map();
  const diaries = [];

  return {
    users,
    orders,
    webhookEvents,
    setupTokens,
    inquiries,
    subscribers,
    diaries,
    getUser(email) {
      return users.get(String(email).toLowerCase()) || null;
    },
    createUser(user) {
      const email = String(user.email).toLowerCase();
      const record = {
        email,
        fullName: user.fullName || "",
        passwordHash: null,
        status: "PENDING_SETUP",
        createdAt: new Date().toISOString()
      };
      users.set(email, record);
      return record;
    },
    setPassword(email, passwordHash) {
      const user = users.get(String(email).toLowerCase());
      if (!user) return null;
      user.passwordHash = passwordHash;
      user.status = "ACTIVE";
      user.updatedAt = new Date().toISOString();
      return user;
    },
    createOrder(order) {
      orders.set(order.id, { ...order, status: "CREATED", createdAt: new Date().toISOString() });
      return orders.get(order.id);
    },
    getOrder(id) {
      return orders.get(id) || null;
    },
    markFulfilled(id) {
      const order = orders.get(id);
      if (!order) return null;
      order.status = "FULFILLED";
      order.fulfilledAt = new Date().toISOString();
      return order;
    },
    hasWebhookEvent(id) {
      return webhookEvents.has(id);
    },
    addWebhookEvent(id) {
      webhookEvents.add(id);
    },
    createSetupToken(hash, email, expiresAt) {
      setupTokens.set(hash, { email: String(email).toLowerCase(), expiresAt, usedAt: null });
    },
    consumeSetupToken(hash) {
      const record = setupTokens.get(hash);
      if (!record) return null;
      if (record.usedAt) return null;
      if (record.expiresAt < Date.now()) return null;
      record.usedAt = Date.now();
      return record;
    },
    addInquiry(inquiry) {
      inquiries.push({ ...inquiry, receivedAt: new Date().toISOString() });
      return inquiries.length;
    },
    addSubscriber(email) {
      const normalized = String(email).toLowerCase();
      if (!subscribers.has(normalized)) {
        subscribers.set(normalized, { email: normalized, createdAt: new Date().toISOString() });
      }
      return subscribers.get(normalized);
    },
    addDiary(entry) {
      diaries.push({ ...entry, status: "PENDING_REVIEW", receivedAt: new Date().toISOString() });
      return diaries.length;
    },
    stats() {
      return {
        users: users.size,
        orders: orders.size,
        fulfilledOrders: [...orders.values()].filter((order) => order.status === "FULFILLED").length,
        webhookEvents: webhookEvents.size,
        inquiries: inquiries.length,
        subscribers: subscribers.size,
        diaries: diaries.length
      };
    }
  };
}
