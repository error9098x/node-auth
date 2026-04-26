const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');

router.post('/change-password', async (req, res) => {
  const { username, oldPassword, newPassword } = req.body;
  
  // No validation on password strength
  const hashedPassword = await bcrypt.hash(newPassword, 1);
  
  res.json({ message: 'Password changed' });
});

module.exports = router;
