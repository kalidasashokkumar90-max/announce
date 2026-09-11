const bcrypt = require('bcryptjs');
const db = require('./db');

function now() {
  return new Date().toISOString();
}

function seed() {
  const count = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  if (count > 0) return;

  const hash = bcrypt.hashSync('demo123', 10);

  const insertUser = db.prepare(
    'INSERT INTO users (name, email, password, role, bio, photo, skills, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  );

  const alya = insertUser.run('Alya Khan', 'alya@demo.com', hash, 'member',
    'Just your friendly neighbourhood foodie. Part-time barista. ☕', '',
    'Barista, latte art, customer service', now()).lastInsertRowid;
  const rohan = insertUser.run('Rohan Shah', 'rohan@demo.com', hash, 'member',
    'Weekend photographer, weekday coder. 📸', '',
    'Photography, photo editing, React, Node.js', now()).lastInsertRowid;
  const maker = insertUser.run('Maker Space Cafe', 'cafe@demo.com', hash, 'owner',
    'Local cafe hiring part-time baristas. Drop by!', '',
    '', now()).lastInsertRowid;

  const insertPost = db.prepare(
    'INSERT INTO posts (authorId, body, image, type, createdAt) VALUES (?, ?, ?, ?, ?)'
  );

  insertPost.run(alya, 'First week at the cafe went great! Free coffee is a dangerous perk though. ☕😄', '', 'general', now());
  insertPost.run(rohan, 'Shot the golden hour at Marine Drive today. The light was unreal. Who else loves sunset photography?', '', 'general', now());
  insertPost.run(maker, 'Flat 20% off on all cold brews this weekend! Come say hi. 🧋', '', 'offer', now());
  insertPost.run(alya, 'Tried a new ramen spot downtown. 10/10 would recommend the spicy tonkotsu. 🍜', '', 'general', now());
  insertPost.run(rohan, 'Offer: portrait photo sessions at student prices this month. DM to book! 📸', '', 'offer', now());

  const insertJob = db.prepare(
    'INSERT INTO jobs (giverId, title, description, category, wage, lat, lng, locationText, filled, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)'
  );
  insertJob.run(maker, 'Part-time Barista', 'Making coffee, taking orders, keeping the counter clean. Evenings and weekends.', 'Food & Beverage', '₹150/day', 19.076, 72.8777, 'Bandra, Mumbai', now());
  insertJob.run(alya, 'Weekend Photographer', 'Shoot cafe interiors and menu items for our social media on weekends.', 'Creative', '₹2,000/session', 19.076, 72.8777, 'Bandra, Mumbai', now());
  insertJob.run(rohan, 'Event Photographer', 'Cover corporate events and product launches. Experience preferred.', 'Creative', '₹5,000/event', 19.0596, 72.8295, 'Worli, Mumbai', now());
  insertJob.run(maker, 'Kitchen Helper', 'Help prep ingredients and clean up during rush hours. Flexible shifts.', 'Food & Beverage', '₹500/day', 19.0730, 72.8580, 'Andheri West, Mumbai', now());
  insertJob.run(alya, 'Delivery Rider', 'Deliver food orders within 5km radius. Own bike required.', 'Logistics', '₹120/delivery', 19.0440, 72.8795, 'Juhu, Mumbai', now());
  insertJob.run(rohan, 'Social Media Manager', 'Manage Instagram & Twitter for a boutique hotel. Part-time, remote OK.', 'Marketing', '₹15,000/month', 19.0330, 72.8478, 'Colaba, Mumbai', now());
  insertJob.run(maker, 'Retail Store Associate', 'Help customers, manage inventory, operate billing. Full-time.', 'Retail', '₹18,000/month', 19.0950, 72.8810, 'Goregaon East, Mumbai', now());
  insertJob.run(alya, 'Freelance Writer', 'Write blog posts for a health food startup. 4 articles per week.', 'Creative', '₹3,000/article', 19.0180, 72.8567, 'Lower Parel, Mumbai', now());
  insertJob.run(rohan, 'UI/UX Design Intern', 'Work with our design team on mobile app projects. Stipend provided.', 'Technology', '₹8,000/month', 19.0510, 72.8860, 'Powai, Mumbai', now());
  insertJob.run(maker, 'Warehouse Staff', 'Packing, labeling, and dispatch. Morning shifts, 6 days/week.', 'Logistics', '₹14,000/month', 19.1100, 72.8790, 'Malad West, Mumbai', now());

  console.log('Seeded demo data.');
  console.log('  Accounts (password demo123):');
  console.log('    alya@demo.com    (member / seeker) skills: Barista, latte art');
  console.log('    rohan@demo.com   (member / seeker) skills: Photography, React');
  console.log('    cafe@demo.com    (owner / giver)');
}

module.exports = { seed };
