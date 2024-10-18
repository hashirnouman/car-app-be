import express, { Request, Response, NextFunction } from 'express';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { v2 as cloudinary } from 'cloudinary';
import multer from 'multer';
import cors from 'cors';
dotenv.config();

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});
const app = express();
const prisma = new PrismaClient();
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });
app.use(express.json());
app.use(cors({
    origin: "*"
}));
// Middleware to verify JWT token
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const authenticateToken = (req: any, res: any, next: NextFunction) => {
    const authHeader = req!.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
   
    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err: any, user: any) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Login user

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Find the user by email
        const user = await prisma.user.findUnique({
            where: { email },
        });

        // If user doesn't exist, return an error
        if (!user) {
            res.status(401).json({ error: 'Invalid email or password' });
        }

        // Compare the provided password with the stored hash
        const isPasswordValid = await bcrypt.compare(password, user!.password);

        if (!isPasswordValid) {
            res.status(401).json({ error: 'Invalid email or password' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { userId: user!.id, email: user!.email },
            JWT_SECRET,
            { expiresIn: '10h' }
        );

        // If password is valid, return success message with token
        res.json({ message: 'Login successful', token });
    } catch (error) {
        res.status(500).json({ error: 'Unable to log in' });
    }
});

const uploadToCloudinary = async (file: Express.Multer.File): Promise<string> => {
    return new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
            { folder: 'car-images' },
            (error, result) => {
                if (error) reject(error);
                resolve(result?.secure_url || '');
            }
        );

        // Convert buffer to stream
        const bufferStream = require('stream').Readable.from(file.buffer);
        bufferStream.pipe(uploadStream);
    });
};

app.post('/car-details', authenticateToken, upload.array('images'), async (req: any, res: any) => {
    try {
        const { carmodel, price } = req.body;
        const files = req.files as Express.Multer.File[];
        const userId = req.user.userId;

        // Validate input
        if (!carmodel || !price || !files || files.length === 0) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Upload images to Cloudinary and get URLs
        const imageUploadPromises = files.map(file => uploadToCloudinary(file));
        const imageUrls = await Promise.all(imageUploadPromises);

        // Create car record
        const car = await prisma.car.create({
            data: {
                name: carmodel,
                price: parseFloat(price)
            }
        });

        // Create image records and associate them with the user
        const imageRecords = await Promise.all(
            imageUrls.map(url =>
                prisma.image.create({
                    data: {
                        url,
                        userId
                    }
                })
            )
        );

        // Send the response here
        return res.json({
            message: 'Car details saved successfully',
            car,
            images: imageRecords
        });

    } catch (error) {
        console.error('Error saving car details:', error);
        // Make sure only one response is sent
        return res.status(500).json({ error: 'Failed to save car details' });
    }
});


const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});