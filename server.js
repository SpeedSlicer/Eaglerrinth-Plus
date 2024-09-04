
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const session = require('express-session');
const bcrypt = require('bcryptjs');

const app = express();
app.use(bodyParser.json());
app.use(express.static('public')); // Serve static files from 'public' folder

const modsFilePath = path.join(__dirname, 'mods.json');
const pendingModsFilePath = path.join(__dirname, 'pendingMods.json');

const admins = [
    { id: 'admin1', password: bcrypt.hashSync('adminpassword', 10) } // Example admin
];
const modMakers = [
    { id: 'modmaker1', password: bcrypt.hashSync('modmakerpassword', 10) } // Example mod maker
];

app.use(session({
    secret: 'your-secret-key', // Replace with a secure secret
    resave: false,
    saveUninitialized: true,
}));

function authenticate(role) {
    return (req, res, next) => {
        if (!req.session.user || req.session.user.role !== role) {
            return res.status(401).json({ message: 'Unauthorized' });
        }
        next();
    };
}

app.post('/signin', (req, res) => {
    const { id, password } = req.body;

    const admin = admins.find(a => a.id === id);
    if (admin) {
        if (bcrypt.compareSync(password, admin.password)) {
            req.session.user = { id, role: 'admin' };
            return res.json({ message: 'Admin signed in' });
        }
    }

    const modMaker = modMakers.find(m => m.id === id);
    if (modMaker) {
        if (bcrypt.compareSync(password, modMaker.password)) {
            req.session.user = { id, role: 'modmaker' };
            return res.json({ message: 'Mod maker signed in' });
        }
    }

    res.status(401).json({ message: 'Invalid credentials' });
});

app.post('/signout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Signed out successfully' });
});

app.post('/upload-mod', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'modmaker') {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    const modData = req.body;
    const modId = generateUniqueId();

    const newMod = {
        id: modId,
        ...modData
    };

    fs.readFile(pendingModsFilePath, (err, data) => {
        if (err && err.code !== 'ENOENT') return res.status(500).json({ message: 'Error reading pendingMods.json' });

        let pendingMods = { mods: [] };
        if (data) {
            try {
                pendingMods = JSON.parse(data);
            } catch (e) {
                return res.status(500).json({ message: 'Error parsing pendingMods.json' });
            }
        }

        pendingMods.mods.push(newMod);

        fs.writeFile(pendingModsFilePath, JSON.stringify(pendingMods, null, 2), (err) => {
            if (err) return res.status(500).json({ message: 'Error updating pendingMods.json' });
            res.json({ message: `Mod uploaded. Your ID is ${modId}.` });
        });
    });
});

app.get('/pending-mods', authenticate('admin'), (req, res) => {
    fs.readFile(pendingModsFilePath, (err, data) => {
        if (err && err.code !== 'ENOENT') return res.status(500).json({ message: 'Error reading pendingMods.json' });

        let pendingMods = { mods: [] };
        if (data) {
            try {
                pendingMods = JSON.parse(data);
            } catch (e) {
                return res.status(500).json({ message: 'Error parsing pendingMods.json' });
            }
        }

        res.json(pendingMods);
    });
});

app.post('/approve-mod/:id', authenticate('admin'), (req, res) => {
    const modId = req.params.id;

    fs.readFile(pendingModsFilePath, (err, data) => {
        if (err && err.code !== 'ENOENT') return res.status(500).json({ message: 'Error reading pendingMods.json' });

        let pendingMods = { mods: [] };
        if (data) {
            try {
                pendingMods = JSON.parse(data);
            } catch (e) {
                return res.status(500).json({ message: 'Error parsing pendingMods.json' });
            }
        }

        const modIndex = pendingMods.mods.findIndex(mod => mod.id === modId);
        if (modIndex === -1) return res.status(404).json({ message: 'Mod not found' });

        const mod = pendingMods.mods.splice(modIndex, 1)[0];

        loadMods((err, mods) => {
            if (err) return res.status(500).json({ message: 'Error reading mods.json' });

            mods.mods.push(mod);

            saveMods(mods, (err) => {
                if (err) return res.status(500).json({ message: 'Error updating mods.json' });

                fs.writeFile(pendingModsFilePath, JSON.stringify(pendingMods, null, 2), (err) => {
                    if (err) return res.status(500).json({ message: 'Error updating pendingMods.json' });
                    res.json({ message: 'Mod approved successfully' });
                });
            });
        });
    });
});

app.post('/deny-mod/:id', authenticate('admin'), (req, res) => {
    const modId = req.params.id;

    fs.readFile(pendingModsFilePath, (err, data) => {
        if (err && err.code !== 'ENOENT') return res.status(500).json({ message: 'Error reading pendingMods.json' });

        let pendingMods = { mods: [] };
        if (data) {
            try {
                pendingMods = JSON.parse(data);
            } catch (e) {
                return res.status(500).json({ message: 'Error parsing pendingMods.json' });
            }
        }

        const modIndex = pendingMods.mods.findIndex(mod => mod.id === modId);
        if (modIndex === -1) return res.status(404).json({ message: 'Mod not found' });

        pendingMods.mods.splice(modIndex, 1);

        fs.writeFile(pendingModsFilePath, JSON.stringify(pendingMods, null, 2), (err) => {
            if (err) return res.status(500).json({ message: 'Error updating pendingMods.json' });
            res.json({ message: 'Mod denied successfully' });
        });
    });
});

function generateUniqueId() {
    return crypto.randomBytes(16).toString('hex');
}

function loadMods(callback) {
    fs.readFile(modsFilePath, (err, data) => {
        if (err) return callback(err);
        try {
            callback(null, JSON.parse(data));
        } catch (e) {
            callback(e);
        }
    });
}

function saveMods(mods, callback) {
    fs.writeFile(modsFilePath, JSON.stringify(mods, null, 2), callback);
}

app.listen(3000, () => {
    console.log('Server running on http://localhost:3000');
});
