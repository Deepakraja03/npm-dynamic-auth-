// index.js

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");

const router = express.Router();

// Signup route
router.post('/signup', async (req, res) => {
    try {
        const { data, model } = req.body;
        const User = model;

        // Check if the model is provided
        if (!User) {
            return res.status(400).json({ message: "Model not provided" });
        }

        const existingUser = await User.findOne(data.query).exec();

        if (existingUser) {
            return res.status(409).json({ message: "User already exists" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(data.password, 10);

        const user = new User({
            ...data.user,
            password: hashedPassword,
        });

        await user.save();
        res.status(201).json({ message: "User is created successfully", user });
    } catch (error) {
        res.status(500).json({ message: "Error creating user", error: error.message });
    }
});

// Login route
router.post('/login', async (req, res) => {
    try {
        const { data, model, jwtSecret } = req.body;
        const User = model;

        // Check if the model is provided
        if (!User) {
            return res.status(400).json({ message: "Model not provided" });
        }

        const user = await User.findOne(data.query);

        if (!user) {
            return res.json({ error: "User not found" });
        }

        if (await bcrypt.compare(data.password, user.password)) {
            const token = jwt.sign({ email: user.email }, jwtSecret, {  // Using jwtSecret from request
                expiresIn: '1h',
            });

            return res.json({ status: 'ok', data: token });
        }

        res.json({ status: 'error', error: 'Invalid Password' });
    } catch (error) {
        res.status(500).json({ message: "Error logging in", error: error.message });
    }
});

module.exports = router;
