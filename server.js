const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ limit: '1mb', extended: true }));

app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:5173', 'https://mango-mushroom-0cf698303.2.azurestaticapps.net/'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('Połączono z MongoDB aplikacja klienta'))
    .catch(err => console.error('Błąd połączenia z MongoDB:', err));

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

const VerificationTokenSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    token: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 3600 }
});
const VerificationToken = mongoose.model('VerificationToken', VerificationTokenSchema);

const ImageSchema = new mongoose.Schema({
    imageData: { type: String, required: true },
    imageType: { type: String, enum: ['product', 'avatar', 'article'], required: true },
    createdAt: { type: Date, default: Date.now }
});
const Image = mongoose.model('Image', ImageSchema);

const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    username: { type: String, required: true, unique: true, trim: true, minlength: 3, maxlength: 30 },
    password: { type: String, required: true, minlength: 8 },
    firstName: { type: String, required: true, trim: true },
    lastName: { type: String, required: true, trim: true },
    avatarImageId: { type: mongoose.Schema.Types.ObjectId, ref: 'Image', default: null },
    favoriteProducts: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product', default: [] }],
    savedArticles: [{ type: String, default: [] }],
    allergies: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Ingredient', default: [] }],
    isVerified: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
});

const CreatorSchema = new mongoose.Schema({
    email: { type: String, required: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    avatarImageId: { type: mongoose.Schema.Types.ObjectId, ref: 'Image', default: null },
});
const Creator = mongoose.model('Creator', CreatorSchema);

const TempUserSchema = new mongoose.Schema({
    email: { type: String, required: true, lowercase: true, trim: true },
    username: { type: String, required: true, trim: true },
    password: { type: String, required: true },
    firstName: { type: String, required: true, trim: true },
    lastName: { type: String, required: true, trim: true },
    verificationToken: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 3600 }
});
const TempUser = mongoose.model('TempUser', TempUserSchema);

const PasswordResetTokenSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    token: { type: String, required: true },
    createdAt: { type: Date, default: Date.now, expires: 3600 }
});
const PasswordResetToken = mongoose.model('PasswordResetToken', PasswordResetTokenSchema);

const IngredientSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true, unique: true },
    safetyLevel: { type: String, required: true, enum: ['bezpieczny', 'akceptowalny', 'lepiej unikać', 'niebezpieczny'] },
    origin: { type: String, required: true, enum: ['naturalne', 'syntetyczne', 'naturalne/syntetyczne'] },
    description: { type: String, required: true, trim: true },
    tags: {
        type: [String], default: [],
        validate: {
            validator: function (tags) { return tags.every(tag => typeof tag === 'string' && tag.trim().length > 0); },
            message: 'Wszystkie tagi muszą być niepustymi tekstami'
        }
    },
    createdAt: { type: Date, default: Date.now }
});

const ReviewSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    productId: { type: mongoose.Schema.Types.ObjectId, ref: 'Product', required: true },
    rating: { type: Number, required: true, min: 1, max: 5 },
    content: { type: String, required: true, trim: true },
    createdAt: { type: Date, default: Date.now }
});
const Review = mongoose.model('Review', ReviewSchema);

const ArticleCommentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    articleId: { type: mongoose.Schema.Types.ObjectId, ref: 'Article', required: true },
    content: { type: String, required: true, trim: true },
    createdAt: { type: Date, default: Date.now }
});
const ArticleComment = mongoose.model('ArticleComment', ArticleCommentSchema);

const ProductSchema = new mongoose.Schema({
    name: { type: String, required: true, trim: true },
    brand: { type: String, trim: true },
    category: { type: String, trim: true },
    subcategory: { type: String, trim: true },
    skinType: [{ type: String, trim: true }],
    purpose: { type: String, trim: true },
    description: { type: String, trim: true },
    imageId: { type: mongoose.Schema.Types.ObjectId, ref: 'Image', default: null },
    rating: { type: Number, default: 0 },
    reviews: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Review', default: [] }],
    ingredients: [{ type: mongoose.Schema.Types.ObjectId, ref: "Ingredient" }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});
ProductSchema.pre('save', function (next) { this.updatedAt = Date.now(); next(); });
const Product = mongoose.model('Product', ProductSchema);

const SkinCareRoutineSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    name: { type: String, required: true, trim: true },
    description: { type: String, trim: true },
    timeOfDay: { type: String, enum: ['Na dzień', 'Na noc'], required: true },
    products: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Product' }],
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

SkinCareRoutineSchema.pre('save', function (next) { this.updatedAt = Date.now(); next(); });
const SkinCareRoutine = mongoose.model('SkinCareRoutine', SkinCareRoutineSchema);

const TagConflictSchema = new mongoose.Schema({
    tag1: { type: String, required: true, trim: true, lowercase: true },
    tag2: { type: String, required: true, trim: true, lowercase: true },
    level: { type: String, enum: ["lekki konflikt", "silny konflikt", "zakazany"], required: true },
    description: { type: String, trim: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const ArticleBlockSchema = new mongoose.Schema({
    article_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Article', required: true },
    type: { type: String, required: true, enum: ['heading', 'paragraph', 'list', 'image'] },
    content: { type: mongoose.Schema.Types.Mixed, required: true },
    order_position: { type: Number, required: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

ArticleBlockSchema.index({ article_id: 1, order_position: 1 });
const ArticleBlock = mongoose.model('ArticleBlock', ArticleBlockSchema);

const ArticleSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    author_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Creator', required: true },
    coverImageId: { type: mongoose.Schema.Types.ObjectId, ref: 'Image', required: true },
    views: { type: Number, default: 0 },
    likes: { type: Number, default: 0 },
    comments_count: { type: Number, default: 0 },
    category: { type: String, trim: true },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

ArticleSchema.pre('save', function (next) {
    this.updatedAt = Date.now();
    next();
});

const Article = mongoose.model('Article', ArticleSchema);
TagConflictSchema.index({ tag1: 1, tag2: 1 }, { unique: true });
TagConflictSchema.index({ tag1: 1 });
TagConflictSchema.index({ tag2: 1 });
TagConflictSchema.pre('save', function (next) { this.updatedAt = Date.now(); next(); });

const User = mongoose.model('User', UserSchema);
const Ingredient = mongoose.model('Ingredient', IngredientSchema);
const TagConflict = mongoose.model('TagConflict', TagConflictSchema);
const ObjectId = mongoose.Types.ObjectId;
const DEFAULT_AVATAR_ID_STRING = '691d02a135df80c6f8b7ba66';
const DEFAULT_AVATAR_OBJECT_ID = new ObjectId(DEFAULT_AVATAR_ID_STRING);

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'Brak tokenu dostępu' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Nieprawidłowy token' });
        req.user = user;
        next();
    });
};

const isValidBase64Image = (base64) => {
    return typeof base64 === 'string' && base64.startsWith('data:image/') && base64.includes(';base64,');
};

const sendVerificationEmail = async (email, token, firstName) => {
    const baseUrl = process.env.FRONTEND_URL.replace(/\/$/, "");
    const verificationUrl = `${baseUrl}/verify-email/${token}`;

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Zweryfikuj swój adres email - Clea',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
                <h2 style="color: #667eea;">Weryfikacja adresu email</h2>
                <p>Cześć ${firstName}!</p>
                <p>Dziękujemy za rejestrację w aplikacji Clea. Aby dokończyć proces rejestracji, kliknij w poniższy przycisk (link ważny przez 1 godzinę):</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${verificationUrl}" style="background-color: #667eea; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">Zweryfikuj adres email</a>
                </div>
                <p>Jeśli to nie Ty zarejestrowałeś się w naszej aplikacji, zignoruj tę wiadomość.</p>
            </div>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log('Email weryfikacyjny wysłany do:', email);
        return true;
    } catch (error) {
        console.error('Błąd wysyłania emaila:', error);
        return false;
    }
};

const sendPasswordResetEmail = async (email, token, firstName) => {
    const baseUrl = process.env.FRONTEND_URL.replace(/\/$/, "");
    const resetUrl = `${baseUrl}/reset-password/${token}`;

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Resetowanie hasła - Clea',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
                <h2 style="color: #667eea;">Resetowanie hasła</h2>
                <p>Cześć ${firstName},</p>
                <p>Otrzymaliśmy prośbę o zresetowanie hasła do Twojego konta w aplikacji Clea.</p>
                <p>Aby ustawić nowe hasło, kliknij w poniższy przycisk (link ważny przez 1 godzinę):</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="${resetUrl}" style="background-color: #667eea; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">Zresetuj hasło</a>
                </div>
                <p>Jeśli to nie Ty wysłałeś tę prośbę, możesz zignorować tę wiadomość.</p>
            </div>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        console.error('Błąd wysyłania emaila resetującego:', error);
        return false;
    }
};

app.get('/api/ping', (req, res) => {
    try {
        res.status(200).json({ message: 'pong' });
    } catch (error) {
        console.error('Ping endpoint error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/auth/register', async (req, res) => {
    try {
        const { email, username, password, firstName, lastName } = req.body;

        if (!email || !username || !password || !firstName || !lastName) {
            return res.status(400).json({ message: 'Wszystkie pola są wymagane' });
        }
        if (password.length < 8) return res.status(400).json({ message: 'Hasło musi mieć min. 8 znaków' });

        const usernameRegex = /^[a-zA-Z0-9_.-]+$/;
        if (!usernameRegex.test(username)) {
            return res.status(400).json({ message: 'Nieprawidłowe znaki w nazwie użytkownika' });
        }
        const existingUser = await User.findOne({
            $or: [{ email: email.toLowerCase() }, { username: username }]
        });
        if (existingUser) {
            return res.status(400).json({ message: 'Użytkownik o takim emailu lub nazwie już istnieje.' });
        }

        const existingTempUser = await TempUser.findOne({
            $or: [{ email: email.toLowerCase() }, { username: username }]
        });

        if (existingTempUser) {
            return res.status(409).json({
                success: false,
                message: 'Konto zostało utworzone, ale niezweryfikowane.',
                requiresVerification: true,
                email: existingTempUser.email
            });
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const verificationToken = crypto.randomBytes(32).toString('hex');
        const tempUser = new TempUser({
            email,
            username,
            password: hashedPassword,
            firstName,
            lastName,
            verificationToken
        });

        await tempUser.save();

        const emailSent = await sendVerificationEmail(email, verificationToken, firstName);

        if (!emailSent) {
            await TempUser.findByIdAndDelete(tempUser._id);
            return res.status(500).json({ message: 'Błąd wysyłania emaila weryfikacyjnego.' });
        }

        res.status(201).json({
            success: true,
            message: 'Link weryfikacyjny został wysłany. Sprawdź email.',
            requiresVerification: true
        });

    } catch (error) {
        console.error('Błąd rejestracji:', error);
        res.status(500).json({ message: 'Błąd serwera podczas rejestracji' });
    }
});

app.get('/api/auth/verify-email/:token', async (req, res) => {
    try {
        const { token } = req.params;

        const tempUser = await TempUser.findOne({ verificationToken: token });

        if (!tempUser) {
            return res.status(400).json({
                message: 'Link weryfikacyjny wygasł lub jest nieprawidłowy.'
            });
        }

        const newUser = new User({
            email: tempUser.email,
            username: tempUser.username,
            password: tempUser.password,
            firstName: tempUser.firstName,
            lastName: tempUser.lastName,
            avatarImageId: DEFAULT_AVATAR_OBJECT_ID,
            favoriteProducts: [],
            savedArticles: [],
            allergies: [],
            isVerified: true
        });

        await newUser.save();
        await TempUser.findByIdAndDelete(tempUser._id);

        const jwtToken = jwt.sign(
            {
                userId: newUser._id,
                email: newUser.email,
                username: newUser.username
            },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        const avatarData = await Image.findById(DEFAULT_AVATAR_OBJECT_ID);

        res.json({
            success: true,
            message: 'Konto zostało pomyślnie utworzone i zweryfikowane!',
            token: jwtToken,
            user: {
                id: newUser._id,
                email: newUser.email,
                username: newUser.username,
                firstName: newUser.firstName,
                lastName: newUser.lastName,
                avatarImageId: newUser.avatarImageId,
                avatarImageData: avatarData?.imageData || null,
                isVerified: true
            }
        });

    } catch (error) {
        console.error('Błąd weryfikacji:', error);
        if (error.code === 11000) {
            return res.status(200).json({ message: 'Konto zostało już zweryfikowane.' });
        }
        res.status(500).json({ message: 'Błąd serwera podczas weryfikacji.' });
    }
});

app.post('/api/auth/resend-verification', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: 'Email jest wymagany' });
        }

        const emailLower = email.toLowerCase();
        const tempUser = await TempUser.findOne({ email: emailLower });

        if (tempUser) {
            const newVerificationToken = crypto.randomBytes(32).toString('hex');
            tempUser.verificationToken = newVerificationToken;
            tempUser.createdAt = new Date();
            await tempUser.save();

            const emailSent = await sendVerificationEmail(tempUser.email, newVerificationToken, tempUser.firstName);

            if (emailSent) {
                return res.json({ message: 'Email weryfikacyjny został wysłany ponownie (Temp).' });
            } else {
                return res.status(500).json({ message: 'Błąd wysyłania emaila.' });
            }
        }
        const user = await User.findOne({ email: emailLower });

        if (!user) {
            return res.status(404).json({ message: 'Użytkownik nie znaleziony' });
        }

        if (user.isVerified) {
            return res.status(400).json({ message: 'Email już został zweryfikowany' });
        }

        await VerificationToken.deleteMany({ userId: user._id });

        const verificationToken = crypto.randomBytes(32).toString('hex');
        const tokenDoc = new VerificationToken({
            userId: user._id,
            token: verificationToken
        });
        await tokenDoc.save();

        const emailSent = await sendVerificationEmail(user.email, verificationToken, user.firstName);

        if (!emailSent) {
            return res.status(500).json({
                message: 'Nie udało się wysłać emaila weryfikacyjnego. Spróbuj ponownie później.'
            });
        }

        res.json({ message: 'Email weryfikacyjny został wysłany ponownie' });

    } catch (error) {
        console.error('Błąd ponownego wysyłania emaila:', error);
        res.status(500).json({ message: 'Błąd serwera' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { login, password } = req.body;

        if (!login || !password) {
            return res.status(400).json({ message: 'Login i hasło są wymagane' });
        }

        const loginQuery = {
            $or: [
                { email: login.toLowerCase() },
                { username: login }
            ]
        };

        let user = await User.findOne(loginQuery).populate('avatarImageId');
        let isTempUser = false;
        if (!user) {
            user = await TempUser.findOne(loginQuery);
            isTempUser = true;
        }

        if (!user) {
            return res.status(400).json({ message: 'Nieprawidłowy login lub hasło' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(400).json({ message: 'Nieprawidłowy login lub hasło' });
        }
        if (isTempUser || (user.isVerified === false)) {
            return res.status(403).json({
                message: 'Twoje konto nie zostało zweryfikowane. Sprawdź swoją skrzynkę email.',
                requiresVerification: true,
                email: user.email
            });
        }

        const token = jwt.sign(
            {
                userId: user._id,
                email: user.email,
                username: user.username
            },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Zalogowano pomyślnie',
            token,
            user: {
                id: user._id,
                email: user.email,
                username: user.username,
                firstName: user.firstName,
                lastName: user.lastName,
                avatarImageId: user.avatarImageId?._id || null,
                avatarImageData: user.avatarImageId?.imageData || null,
                favoriteProducts: user.favoriteProducts,
                savedArticles: user.savedArticles,
                allergies: user.allergies,
                isVerified: true
            }
        });

    } catch (error) {
        console.error('Błąd logowania:', error);
        res.status(500).json({ message: 'Błąd serwera podczas logowania' });
    }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: 'Proszę podać adres email' });
        }

        const user = await User.findOne({ email: email.toLowerCase() });

        if (!user) {
            return res.json({ message: 'Jeśli podany email istnieje w bazie, wysłaliśmy na niego link resetujący.' });
        }

        await PasswordResetToken.deleteMany({ userId: user._id });

        const resetToken = crypto.randomBytes(32).toString('hex');
        const tokenDoc = new PasswordResetToken({
            userId: user._id,
            token: resetToken
        });
        await tokenDoc.save();

        const emailSent = await sendPasswordResetEmail(user.email, resetToken, user.firstName);

        if (!emailSent) {
            return res.status(500).json({ message: 'Wystąpił błąd podczas wysyłania emaila.' });
        }

        res.json({ message: 'Jeśli podany email istnieje w bazie, wysłaliśmy na niego link resetujący.' });

    } catch (error) {
        console.error('Błąd resetowania hasła:', error);
        res.status(500).json({ message: 'Błąd serwera' });
    }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;

        if (!token || !newPassword) {
            return res.status(400).json({ message: 'Brakujące dane.' });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({ message: 'Hasło musi mieć co najmniej 8 znaków.' });
        }

        const resetTokenDoc = await PasswordResetToken.findOne({ token });

        if (!resetTokenDoc) {
            return res.status(400).json({ message: 'Link resetujący jest nieprawidłowy lub wygasł.' });
        }

        const user = await User.findById(resetTokenDoc.userId);
        if (!user) {
            return res.status(404).json({ message: 'Użytkownik nie istnieje.' });
        }

        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        user.password = hashedPassword;
        await user.save();

        await PasswordResetToken.findByIdAndDelete(resetTokenDoc._id);

        res.json({ message: 'Hasło zostało zmienione pomyślnie. Możesz się teraz zalogować.' });

    } catch (error) {
        console.error('Błąd zmiany hasła:', error);
        res.status(500).json({ message: 'Błąd serwera podczas zmiany hasła.' });
    }
});

app.get('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId)
            .select('-password')
            .populate('favoriteProducts')
            .populate('allergies')
            .populate('avatarImageId');

        if (!user) {
            return res.status(404).json({ message: 'Użytkownik nie znaleziony' });
        }

        const allergiesIds = user.allergies.map(allergy =>
            typeof allergy === 'object' && allergy._id ? allergy._id.toString() : allergy.toString()
        );
        const favoriteProductIds = user.favoriteProducts.map(product =>
            typeof product === 'object' && product._id ? product._id.toString() : product.toString()
        );

        res.json({
            id: user._id,
            email: user.email,
            username: user.username,
            firstName: user.firstName,
            lastName: user.lastName,
            avatarImageId: user.avatarImageId?._id || null,
            avatarImageData: user.avatarImageId?.imageData || null,
            favoriteProducts: favoriteProductIds,
            savedArticles: user.savedArticles,
            allergies: allergiesIds,
            createdAt: user.createdAt
        });
    } catch (error) {
        console.error('Błąd pobierania profilu:', error);
        res.status(500).json({ message: 'Błąd serwera' });
    }
});

app.put('/api/auth/profile', authenticateToken, async (req, res) => {
    try {
        const {
            firstName,
            lastName,
            username,
            email,
            avatarBase64,
            favoriteProducts,
            savedArticles,
            allergies,
            currentPassword,
            newPassword
        } = req.body;

        const user = await User.findById(req.user.userId);
        if (!user) {
            return res.status(404).json({ message: 'Użytkownik nie znaleziony' });
        }

        const updateData = {};

        if (currentPassword || newPassword) {
            if (!currentPassword || !newPassword) {
                return res.status(400).json({
                    message: 'Aby zmienić hasło, musisz podać bieżące i nowe hasło.'
                });
            }

            const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
            if (!isPasswordValid) {
                return res.status(400).json({
                    message: 'Bieżące hasło jest nieprawidłowe'
                });
            }

            if (newPassword.length < 8) {
                return res.status(400).json({
                    message: 'Nowe hasło musi mieć co najmniej 8 znaków'
                });
            }

            const saltRounds = 10;
            updateData.password = await bcrypt.hash(newPassword, saltRounds);
        }

        if (firstName !== undefined) updateData.firstName = firstName.trim();
        if (lastName !== undefined) updateData.lastName = lastName.trim();

        if (username !== undefined && username.trim() !== user.username) {
            const existingUser = await User.findOne({
                username: username.trim(),
                _id: { $ne: req.user.userId }
            });
            if (existingUser) {
                return res.status(400).json({
                    message: 'Ta nazwa użytkownika jest już zajęta'
                });
            }
            const usernameRegex = /^[a-zA-Z0-9_.-]+$/;
            if (username.length < 3 || username.length > 30 || !usernameRegex.test(username)) {
                return res.status(400).json({
                    message: 'Nazwa Użytkownika musi mieć od 3 do 30 znaków i może zawierać tylko litery, cyfry, kropki, podkreślenia i myślniki'
                });
            }
            updateData.username = username.trim();
        }

        if (email !== undefined && email.trim() !== user.email) {
            const existingUser = await User.findOne({
                email: email.trim(),
                _id: { $ne: req.user.userId }
            });
            if (existingUser) {
                return res.status(400).json({
                    message: 'Ten email jest już używany'
                });
            }
            updateData.email = email.trim();
        }

        if (avatarBase64 !== undefined) {
            if (avatarBase64 === null || avatarBase64 === '') {
                if (user.avatarImageId && user.avatarImageId.toString() !== DEFAULT_AVATAR_ID_STRING) {
                    await Image.findByIdAndDelete(user.avatarImageId);
                }
                updateData.avatarImageId = DEFAULT_AVATAR_OBJECT_ID;
            }
            else if (isValidBase64Image(avatarBase64)) {
                if (user.avatarImageId && user.avatarImageId.toString() !== DEFAULT_AVATAR_ID_STRING) {
                    await Image.findByIdAndDelete(user.avatarImageId);
                }
                const newAvatar = new Image({
                    imageData: avatarBase64,
                    imageType: 'avatar'
                });
                await newAvatar.save();
                updateData.avatarImageId = newAvatar._id;
            } else {
                return res.status(400).json({
                    message: 'Nieprawidłowy format zdjęcia profilowego'
                });
            }
        }

        if (favoriteProducts !== undefined && Array.isArray(favoriteProducts)) updateData.favoriteProducts = favoriteProducts;
        if (savedArticles !== undefined && Array.isArray(savedArticles)) updateData.savedArticles = savedArticles;
        if (allergies !== undefined && Array.isArray(allergies)) updateData.allergies = allergies;

        const updatedUser = await User.findByIdAndUpdate(
            req.user.userId,
            updateData,
            { new: true, select: '-password' }
        ).populate('favoriteProducts').populate('allergies').populate('avatarImageId');

        res.json({
            message: 'Profil zaktualizowany pomyślnie',
            user: {
                ...updatedUser.toObject(),
                avatarImageData: updatedUser.avatarImageId?.imageData || null
            }
        });
    } catch (error) {
        console.error('Błąd aktualizacji profilu:', error);
        res.status(500).json({ message: 'Błąd serwera podczas aktualizacji profilu' });
    }
});

app.post('/api/auth/favorites/:productId', authenticateToken, async (req, res) => {
    try {
        const { productId } = req.params;

        if (!mongoose.Types.ObjectId.isValid(productId)) {
            return res.status(400).json({ message: 'Nieprawidłowy ID produktu' });
        }

        const user = await User.findById(req.user.userId);

        if (!user.favoriteProducts.includes(productId)) {
            user.favoriteProducts.push(productId);
            await user.save();
        }

        res.json({
            message: 'Produkt dodany do ulubionych',
            favoriteProducts: user.favoriteProducts
        });
    } catch (error) {
        console.error('Błąd dodawania do ulubionych:', error);
        res.status(500).json({ message: 'Błąd serwera' });
    }
});

app.delete('/api/auth/favorites/:productId', authenticateToken, async (req, res) => {
    try {
        const { productId } = req.params;

        const user = await User.findById(req.user.userId);
        user.favoriteProducts = user.favoriteProducts.filter(id => id.toString() !== productId);
        await user.save();

        res.json({
            message: 'Produkt usunięty z ulubionych',
            favoriteProducts: user.favoriteProducts
        });
    } catch (error) {
        console.error('Błąd usuwania z ulubionych:', error);
        res.status(500).json({ message: 'Błąd serwera' });
    }
});

app.post('/api/auth/allergies/:ingredientId', authenticateToken, async (req, res) => {
    try {
        const { ingredientId } = req.params;

        if (!mongoose.Types.ObjectId.isValid(ingredientId)) {
            return res.status(400).json({ message: 'Nieprawidłowy ID składnika' });
        }

        const user = await User.findById(req.user.userId);

        if (!user.allergies.includes(ingredientId)) {
            user.allergies.push(ingredientId);
            await user.save();
        }

        res.json({
            message: 'Alergia dodana',
            allergies: user.allergies
        });
    } catch (error) {
        console.error('Błąd dodawania alergii:', error);
        res.status(500).json({ message: 'Błąd serwera' });
    }
});

app.delete('/api/auth/allergies/:ingredientId', authenticateToken, async (req, res) => {
    try {
        const { ingredientId } = req.params;

        if (!mongoose.Types.ObjectId.isValid(ingredientId)) {
            return res.status(400).json({ message: 'Nieprawidłowy ID składnika' });
        }

        const user = await User.findById(req.user.userId);
        user.allergies = user.allergies.filter(id => id.toString() !== ingredientId);

        await user.save();

        res.json({
            message: 'Alergia usunięta',
            allergies: user.allergies
        });
    } catch (error) {
        console.error('Błąd usuwania alergii:', error);
        res.status(500).json({ message: 'Błąd serwera' });
    }
});

app.post('/api/auth/saved-articles/:articleId', authenticateToken, async (req, res) => {
    try {
        const { articleId } = req.params;
        const user = await User.findById(req.user.userId);

        if (!user.savedArticles.includes(articleId)) {
            user.savedArticles.push(articleId);
            await user.save();
        }

        res.json({ savedArticles: user.savedArticles });
    } catch (error) {
        res.status(500).json({ message: 'Error' });
    }
});

app.delete('/api/auth/saved-articles/:articleId', authenticateToken, async (req, res) => {
    try {
        const { articleId } = req.params;
        const user = await User.findById(req.user.userId);

        user.savedArticles = user.savedArticles.filter(id => id.toString() !== articleId);
        await user.save();

        res.json({ savedArticles: user.savedArticles });
    } catch (error) {
        res.status(500).json({ message: 'Error' });
    }
});

app.get('/api/auth/verify-token', authenticateToken, (req, res) => {
    res.json({
        valid: true,
        user: {
            id: req.user.userId,
            email: req.user.email,
            username: req.user.username
        }
    });
});

app.get('/api/auth/check-username/:username', async (req, res) => {
    try {
        const { username } = req.params;

        if (username.length < 3 || username.length > 30) {
            return res.status(400).json({
                available: false,
                message: 'Nazwa Użytkownika musi mieć od 3 do 30 znaków'
            });
        }

        const usernameRegex = /^[a-zA-Z0-9_.-]+$/;
        if (!usernameRegex.test(username)) {
            return res.status(400).json({
                available: false,
                message: 'Nazwa Użytkownika może zawierać tylko litery, cyfry, kropki, podkreślenia i myślniki'
            });
        }

        const existingUser = await User.findOne({ username });

        res.json({
            available: !existingUser,
            message: existingUser ? 'Ta nazwa Użytkownika jest już zajęta' : 'Nazwa Użytkownika jest dostępna'
        });
    } catch (error) {
        console.error('Błąd sprawdzania nazwy użytkownika:', error);
        res.status(500).json({
            available: false,
            message: 'Błąd serwera'
        });
    }
});

app.get('/api/products', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 12;
        const skip = (page - 1) * limit;

        const total = await Product.countDocuments();
        const products = await Product.find()
            .populate('imageId')
            .populate('reviews')
            .populate('ingredients', 'name safetyLevel')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);

        const productsWithImages = products.map(product => ({
            ...product.toObject(),
            imageData: null,
            imageId: product.imageId?._id || null,
            reviewCount: product.reviews ? product.reviews.length : 0
        }));

        res.json({
            products: productsWithImages,
            hasMore: total > skip + products.length,
            totalCount: total
        });
    } catch (error) {
        console.error('Błąd pobierania produktów:', error);
        res.status(500).json({ message: 'Błąd serwera podczas pobierania produktów' });
    }
});
app.get('/api/products/search', async (req, res) => {
    try {
        const { q } = req.query;

        if (!q || q.trim().length < 1) {
            return res.json({ products: [], count: 0 });
        }

        const products = await Product.find({
            $or: [
                { name: { $regex: q, $options: 'i' } },
                { brand: { $regex: q, $options: 'i' } }
            ]
        })
            .populate('imageId')
            .populate('ingredients')
            .limit(15);

        const productsWithImages = products.map(product => ({
            ...product.toObject(),
            imageData: product.imageId?.imageData || null
        }));

        res.status(200).json({
            products: productsWithImages,
            count: productsWithImages.length
        });
    } catch (error) {
        console.error('Błąd wyszukiwania:', error);
        res.status(500).json({ message: 'Błąd serwera' });
    }
});
app.get('/api/products/:id', async (req, res) => {
    try {
        const { id } = req.params;
        if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ message: 'Nieprawidłowy ID produktu' });

        const product = await Product.findById(id)
            .populate('ingredients')
            .populate('imageId')
            .populate({
                path: 'reviews',
                populate: {
                    path: 'userId',
                    select: 'username avatarImageId',
                    populate: {
                        path: 'avatarImageId',
                        model: 'Image',
                        select: 'imageData'
                    }
                }
            });

        if (!product) return res.status(404).json({ message: 'Produkt nie znaleziony' });

        const productWithImage = {
            ...product.toObject(),
            imageData: product.imageId?.imageData || null
        };

        res.json(productWithImage);
    } catch (error) {
        console.error('Błąd pobierania produktu:', error);
        res.status(500).json({ message: 'Błąd serwera podczas pobierania produktu' });
    }
});

app.post('/api/products/check-compatibility', authenticateToken, async (req, res) => {
    try {
        const { productIds } = req.body;
        if (!productIds || productIds.length < 2) return res.status(400).json({ message: 'Min. 2 produkty' });

        const user = await User.findById(req.user.userId).populate('allergies');
        const userAllergenIds = user.allergies.map(a => a._id.toString());

        const products = await Product.find({ _id: { $in: productIds } }).populate('ingredients');

        const allTags = new Set();
        const tagToIngredients = {};

        products.forEach(product => {
            product.ingredients.forEach(ing => {
                ing.tags.forEach(tag => {
                    const tagLower = tag.toLowerCase();
                    allTags.add(tagLower);
                    if (!tagToIngredients[tagLower]) tagToIngredients[tagLower] = [];
                    tagToIngredients[tagLower].push({
                        ingredientName: ing.name,
                        productName: product.name,
                        productId: product._id
                    });
                });
            });
        });

        const tagsArray = Array.from(allTags);
        const potentialConflicts = await TagConflict.find({
            tag1: { $in: tagsArray },
            tag2: { $in: tagsArray }
        });

        const conflictLookup = new Map();
        potentialConflicts.forEach(conf => {
            conflictLookup.set(`${conf.tag1}|${conf.tag2}`, conf);
            conflictLookup.set(`${conf.tag2}|${conf.tag1}`, conf);
        });

        const conflicts = [];
        let overallConflictLevel = 'brak';

        for (let i = 0; i < tagsArray.length; i++) {
            for (let j = i + 1; j < tagsArray.length; j++) {
                const tag1 = tagsArray[i];
                const tag2 = tagsArray[j];
                const conflict = conflictLookup.get(`${tag1}|${tag2}`);

                if (conflict) {
                    const list1 = tagToIngredients[tag1];
                    const list2 = tagToIngredients[tag2];

                    list1.forEach(item1 => {
                        list2.forEach(item2 => {
                            if (item1.productId.toString() !== item2.productId.toString()) {
                                conflicts.push({
                                    ingredient1: item1.ingredientName,
                                    ingredient2: item2.ingredientName,
                                    product1: item1.productName,
                                    product2: item2.productName,
                                    conflictLevel: conflict.level,
                                    description: conflict.description
                                });

                                if (conflict.level === 'zakazany') overallConflictLevel = 'zakazany';
                                else if (conflict.level === 'silny konflikt' && overallConflictLevel !== 'zakazany') overallConflictLevel = 'silny konflikt';
                                else if (conflict.level === 'lekki konflikt' && overallConflictLevel === 'brak') overallConflictLevel = 'lekki konflikt';
                            }
                        });
                    });
                }
            }
        }

        const allergenWarnings = [];
        products.forEach(p => {
            p.ingredients.forEach(ing => {
                if (userAllergenIds.includes(ing._id.toString())) {
                    allergenWarnings.push({ ingredientName: ing.name, productName: p.name });
                }
            });
        });

        if (allergenWarnings.length > 0) overallConflictLevel = 'zakazany';

        res.json({ overallConflictLevel, conflicts, allergenWarnings });
    } catch (error) {
        res.status(500).json({ message: 'Błąd analizy' });
    }
});
app.post('/api/products/:id/reviews', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { rating, content } = req.body;

        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ message: 'Nieprawidłowy ID produktu' });
        }

        const product = await Product.findById(id);
        if (!product) return res.status(404).json({ message: 'Produkt nie znaleziony' });

        const newReview = new Review({
            userId: req.user.userId,
            productId: id,
            rating: Number(rating),
            content: content.trim()
        });

        await newReview.save();
        product.reviews.push(newReview._id);

        const allReviews = await Review.find({ productId: id });
        const totalRating = allReviews.reduce((sum, review) => sum + review.rating, 0);

        product.rating = totalRating / allReviews.length;

        await product.save();

        res.status(201).json({
            message: 'Opinia dodana pomyślnie',
            review: newReview,
            newAverageRating: product.rating
        });

    } catch (error) {
        console.error('Błąd dodawania opinii:', error);
        res.status(500).json({ message: 'Błąd serwera' });
    }
});

app.delete('/api/products/:productId/reviews/:reviewId', authenticateToken, async (req, res) => {
    try {
        const { productId, reviewId } = req.params;

        const review = await Review.findById(reviewId);
        if (!review) return res.status(404).json({ message: 'Opinia nie znaleziona' });

        await Review.findByIdAndDelete(reviewId);

        const product = await Product.findById(productId);
        if (product) {
            product.reviews = product.reviews.filter(id => id.toString() !== reviewId);

            const remainingReviews = await Review.find({ productId: productId });
            if (remainingReviews.length > 0) {
                const totalRating = remainingReviews.reduce((sum, r) => sum + r.rating, 0);
                product.rating = totalRating / remainingReviews.length;
            } else {
                product.rating = 0;
            }

            await product.save();
        }

        res.json({
            message: 'Opinia usunięta pomyślnie',
            newAverageRating: product ? product.rating : 0
        });
    } catch (error) {
        res.status(500).json({ message: 'Błąd serwera' });
    }
});

app.get('/api/ingredients', async (req, res) => {
    try {
        const ingredients = await Ingredient.find().sort({ name: 1 });
        res.json(ingredients);
    } catch (error) {
        console.error('Błąd pobierania składników:', error);
        res.status(500).json({
            message: 'Błąd serwera podczas pobierania składników'
        });
    }
});

app.get('/api/ingredients/:id', async (req, res) => {
    try {
        const { id } = req.params;

        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({
                message: 'Nieprawidłowy ID składnika'
            });
        }

        const ingredient = await Ingredient.findById(id);

        if (!ingredient) {
            return res.status(404).json({
                message: 'Składnik nie znaleziony'
            });
        }

        res.json(ingredient);
    } catch (error) {
        console.error('Błąd pobierania składnika:', error);
        res.status(500).json({
            message: 'Błąd serwera podczas pobierania składnika'
        });
    }
});

app.get('/api/ingredients/tags', async (req, res) => {
    try {
        const ingredients = await Ingredient.find({}, 'tags');
        const tags = [...new Set(ingredients.flatMap(i => i.tags))].sort();
        res.json(tags);
    } catch (error) {
        console.error('Błąd pobierania tagów:', error);
        res.status(500).json({ message: 'Błąd serwera podczas pobierania tagów' });
    }
});

app.post('/api/cosmetics/analyze', async (req, res) => {
    try {
        const { composition } = req.body;
        if (!composition) return res.status(400).json({ message: 'Brak składu' });

        const ingredientNames = composition.split(',')
            .map(item => item.trim())
            .filter(item => item !== "");

        const totalIngredients = ingredientNames.length;

        const escapeRegExp = (string) => {
            return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        };

        const identifiedIngredients = await Ingredient.find({
            name: {
                $in: ingredientNames.map(name => new RegExp(`^${escapeRegExp(name)}$`, 'i'))
            }
        });

        const safetyStats = {
            bezpieczny: 0,
            akceptowalny: 0,
            'lepiej unikać': 0,
            niebezpieczny: 0,
            niezidentyfikowany: 0
        };

        identifiedIngredients.forEach(ing => {
            if (safetyStats[ing.safetyLevel] !== undefined) {
                safetyStats[ing.safetyLevel]++;
            }
        });

        const identifiedNamesLower = identifiedIngredients.map(i => i.name.toLowerCase());

        const unidentifiedIngredients = ingredientNames.filter(name =>
            !identifiedNamesLower.includes(name.toLowerCase())
        );

        safetyStats.niezidentyfikowany = unidentifiedIngredients.length;

        const productTags = [...new Set(identifiedIngredients.flatMap(ing => ing.tags || []))];

        const detectedConflicts = await TagConflict.find({
            $and: [
                { tag1: { $in: productTags } },
                { tag2: { $in: productTags } }
            ]
        });
        res.json({
            totalIngredients,
            identifiedIngredientsCount: identifiedIngredients.length,
            ingredients: identifiedIngredients,
            unidentifiedIngredients,
            safetyStats,
            conflicts: detectedConflicts
        });

    } catch (error) {
        console.error('Błąd analizy:', error);
        res.status(500).json({ message: 'Wystąpił błąd podczas analizy składu' });
    }
});

app.get('/api/tag-conflicts', async (req, res) => {
    try {
        const conflicts = await TagConflict.find().sort({ createdAt: -1 });
        res.json(conflicts);
    } catch (error) {
        console.error('Błąd pobierania konfliktów:', error);
        res.status(500).json({ message: 'Błąd serwera podczas pobierania konfliktów' });
    }
});

app.get('/api/images/:id', async (req, res) => {
    try {
        const image = await Image.findById(req.params.id);
        if (!image) return res.status(404).send('Image not found');
        const matches = image.imageData.match(/^data:([A-Za-z-+\/]+);base64,(.+)$/);
        if (!matches || matches.length !== 3) {
            return res.status(400).send('Invalid image data');
        }

        const type = matches[1];
        const buffer = Buffer.from(matches[2], 'base64');
        res.writeHead(200, {
            'Content-Type': type,
            'Content-Length': buffer.length,
            'Cache-Control': 'public, max-age=86400'
        });
        res.end(buffer);
    } catch (error) {
        console.error(error);
        res.status(500).send('Error');
    }
});

app.get('/api/articles', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 9;
        const skip = (page - 1) * limit;

        const total = await Article.countDocuments();
        const articles = await Article.find()
            .populate({
                path: 'author_id',
                select: 'firstName lastName avatarImageId',
                populate: {
                    path: 'avatarImageId',
                    model: 'Image',
                    select: '_id'
                }
            })
            .populate('coverImageId', '_id')
            .sort({ createdAt: -1 })
            .skip(skip)
            .limit(limit);
        res.json({
            articles: articles,
            totalPages: Math.ceil(total / limit),
            currentPage: page
        });
    } catch (error) {
        console.error('Błąd pobierania artykułów:', error);
        res.status(500).json({ message: 'Błąd serwera' });
    }
});

app.post('/api/articles/batch', async (req, res) => {
    try {
        const { ids } = req.body;

        if (!ids || !Array.isArray(ids)) {
            return res.status(400).json({ message: 'Nieprawidłowa lista ID' });
        }
        const articles = await Article.find({ _id: { $in: ids } })
            .populate({
                path: 'author_id',
                select: 'firstName lastName avatarImageId',
                populate: {
                    path: 'avatarImageId',
                    model: 'Image',
                    select: '_id'
                }
            })
            .populate('coverImageId', '_id')
            .sort({ createdAt: -1 });

        res.json(articles);
    } catch (error) {
        console.error('Błąd pobierania grupy artykułów:', error);
        res.status(500).json({ message: 'Błąd serwera' });
    }
});

app.get('/api/articles/:id', async (req, res) => {
    try {
        const { id } = req.params;

        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ message: 'Nieprawidłowy ID artykułu' });
        }

        const article = await Article.findById(id)
            .populate({
                path: 'author_id',
                select: 'firstName lastName avatarImageId',
                populate: {
                    path: 'avatarImageId',
                    model: 'Image',
                    select: 'imageData'
                }
            })
            .populate('coverImageId');

        if (!article) {
            return res.status(404).json({ message: 'Artykuł nie znaleziony' });
        }

        const blocks = await ArticleBlock.find({ article_id: id })
            .sort({ order_position: 1 });

        const blocksWithImages = await Promise.all(
            blocks.map(async (block) => {
                if (block.type === 'image' && block.content.imageId) {
                    const image = await Image.findById(block.content.imageId);
                    return {
                        ...block.toObject(),
                        content: {
                            ...block.content,
                            imageData: image?.imageData || null
                        }
                    };
                }
                return block.toObject();
            })
        );

        const authorData = article.author_id ? {
            ...article.author_id.toObject(),
            avatarImageData: article.author_id?.avatarImageId?.imageData || null
        } : { firstName: 'Autor', lastName: 'Nieznany' };

        res.json({
            ...article.toObject(),
            coverImageData: article.coverImageId?.imageData || null,
            author_id: authorData,
            blocks: blocksWithImages
        });
    } catch (error) {
        console.error('Błąd pobierania artykułu:', error);
        res.status(500).json({ message: 'Błąd serwera' });
    }
});

app.post('/api/articles/:id/view', async (req, res) => {
    try {
        const { id } = req.params;
        await Article.findByIdAndUpdate(id, { $inc: { views: 1 } });
        res.json({ message: 'Views increased' });
    } catch (error) {
        res.status(500).json({ message: 'Error' });
    }
});


app.post('/api/articles/:id/like', async (req, res) => {
    try {
        const { id } = req.params;
        await Article.findByIdAndUpdate(id, { $inc: { likes: 1 } });
        res.json({ message: 'Liked' });
    } catch (error) {
        res.status(500).json({ message: 'Error' });
    }
});


app.post('/api/articles/:id/unlike', async (req, res) => {
    try {
        const { id } = req.params;
        await Article.findByIdAndUpdate(id, { $inc: { likes: -1 } });
        res.json({ message: 'Unliked' });
    } catch (error) {
        res.status(500).json({ message: 'Error' });
    }
});

app.get('/api/articles/:id/comments', async (req, res) => {
    try {
        const { id } = req.params;

        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ message: 'Nieprawidłowy ID artykułu' });
        }

        const comments = await ArticleComment.find({ articleId: id })
            .populate({
                path: 'userId',
                select: 'username avatarImageId',
                populate: {
                    path: 'avatarImageId',
                    model: 'Image',
                    select: 'imageData'
                }
            })
            .sort({ createdAt: -1 });

        res.json(comments);
    } catch (error) {
        console.error('Błąd pobierania komentarzy:', error);
        res.status(500).json({ message: 'Błąd serwera podczas pobierania komentarzy' });
    }
});

app.post('/api/articles/:id/comments', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { content } = req.body;

        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ message: 'Nieprawidłowy ID artykułu' });
        }

        if (!content || !content.trim()) {
            return res.status(400).json({ message: 'Treść komentarza jest wymagana' });
        }

        const article = await Article.findById(id);
        if (!article) {
            return res.status(404).json({ message: 'Artykuł nie znaleziony' });
        }

        const newComment = new ArticleComment({
            userId: req.user.userId,
            articleId: id,
            content: content.trim()
        });

        await newComment.save();
        await Article.findByIdAndUpdate(id, { $inc: { comments_count: 1 } });

        const populatedComment = await ArticleComment.findById(newComment._id)
            .populate({
                path: 'userId',
                select: 'username avatarImageId',
                populate: {
                    path: 'avatarImageId',
                    model: 'Image',
                    select: 'imageData'
                }
            });

        res.status(201).json({
            message: 'Komentarz dodany pomyślnie',
            comment: populatedComment
        });

    } catch (error) {
        console.error('Błąd dodawania komentarza:', error);
        res.status(500).json({ message: 'Błąd serwera podczas dodawania komentarza' });
    }
});

app.delete('/api/articles/:articleId/comments/:commentId', authenticateToken, async (req, res) => {
    try {
        const { articleId, commentId } = req.params;

        if (!mongoose.Types.ObjectId.isValid(commentId)) {
            return res.status(400).json({ message: 'Nieprawidłowy ID komentarza' });
        }

        const comment = await ArticleComment.findById(commentId);

        if (!comment) {
            return res.status(404).json({ message: 'Komentarz nie znaleziony' });
        }

        if (comment.userId.toString() !== req.user.userId) {
            return res.status(403).json({ message: 'Brak uprawnień do usunięcia tego komentarza' });
        }

        await ArticleComment.findByIdAndDelete(commentId);
        await Article.findByIdAndUpdate(articleId, { $inc: { comments_count: -1 } });

        res.json({ message: 'Komentarz usunięty pomyślnie' });

    } catch (error) {
        console.error('Błąd usuwania komentarza:', error);
        res.status(500).json({ message: 'Błąd serwera podczas usuwania komentarza' });
    }
});

app.delete('/api/products/:id', async (req, res) => {
    try {
        const { id } = req.params;
        if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ message: 'Nieprawidłowy ID produktu' });

        const product = await Product.findById(id);
        if (!product) return res.status(404).json({ message: 'Produkt nie znaleziony' });

        if (product.imageId) await Image.findByIdAndDelete(product.imageId);

        await Review.deleteMany({ productId: id });

        await Product.findByIdAndDelete(id);

        res.json({ message: 'Produkt, powiązane zdjęcie i opinie usunięte pomyślnie' });
    } catch (error) {
        console.error('Błąd usuwania produktu:', error);
        res.status(500).json({ message: 'Błąd serwera' });
    }
});

app.get('/api/skincare-routines', authenticateToken, async (req, res) => {
    try {
        const routines = await SkinCareRoutine.find({ userId: req.user.userId })
            .populate({
                path: 'products',
                populate: { path: 'imageId' }
            })
            .sort({ createdAt: -1 });

        const routinesMapped = routines.map(r => ({
            ...r.toObject(),
            products: r.products.map(p => ({
                ...p.toObject(),
                imageData: p.imageId?.imageData || null
            }))
        }));

        res.json(routinesMapped);
    } catch (e) { res.status(500).json({ message: 'Błąd' }); }
});

app.post('/api/skincare-routines', authenticateToken, async (req, res) => {
    try {
        const { name, description, timeOfDay, products } = req.body;
        const newRoutine = new SkinCareRoutine({
            userId: req.user.userId,
            name, description, timeOfDay, products
        });
        await newRoutine.save();
        res.status(201).json({ message: 'Zapisano' });
    } catch (e) { res.status(500).json({ message: 'Błąd' }); }
});

app.delete('/api/skincare-routines/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        const routine = await SkinCareRoutine.findOne({
            _id: id,
            userId: req.user.userId
        });

        if (!routine) {
            return res.status(404).json({
                message: 'Pielęgnacja nie znaleziona'
            });
        }

        await SkinCareRoutine.findByIdAndDelete(id);

        res.json({
            message: 'Pielęgnacja usunięta pomyślnie'
        });

    } catch (error) {
        console.error('Błąd usuwania pielęgnacji:', error);
        res.status(500).json({
            message: 'Błąd serwera podczas usuwania pielęgnacji'
        });
    }
});

app.put('/api/skincare-routines/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { name, description, timeOfDay, products } = req.body;

        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({
                message: 'Nieprawidłowy ID pielęgnacji'
            });
        }

        if (!name || !timeOfDay || !products || products.length === 0) {
            return res.status(400).json({
                message: 'Nazwa, pora dnia i produkty są wymagane'
            });
        }

        const routine = await SkinCareRoutine.findOne({
            _id: id,
            userId: req.user.userId
        });

        if (!routine) {
            return res.status(404).json({
                message: 'Pielęgnacja nie znaleziona lub nie masz uprawnień do jej edycji'
            });
        }

        routine.name = name;
        routine.description = description || '';
        routine.timeOfDay = timeOfDay;
        routine.products = products;
        routine.updatedAt = Date.now();

        await routine.save();

        const populatedRoutine = await SkinCareRoutine.findById(routine._id)
            .populate({
                path: 'products',
                populate: {
                    path: 'imageId'
                }
            });

        const routineWithImages = {
            ...populatedRoutine.toObject(),
            products: populatedRoutine.products.map(product => ({
                ...product.toObject(),
                imageData: product.imageId?.imageData || null
            }))
        };

        res.json({
            message: 'Pielęgnacja zaktualizowana pomyślnie',
            routine: routineWithImages
        });

    } catch (error) {
        console.error('Błąd aktualizacji pielęgnacji:', error);
        res.status(500).json({
            message: 'Błąd serwera podczas aktualizacji pielęgnacji'
        });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Serwer działa na porcie ${PORT}`);
});