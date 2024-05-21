import mongoose, { SchemaDefinition } from 'mongoose';
import validator from 'validator';

const userSchemaDefinition: SchemaDefinition = {
    username: {
        type: String,
        required: [true, 'Username is required'],
        minlength: 3,
        maxlength: 64,
        trim: true,
        unique: true,
    },
    email: {
        type: String,
        required: [true, 'Email is required'],
        validate: {
            validator: (value: string) => validator.isEmail(value),
            message: 'Please provide a valid email',
        },
        unique: true,
    },
    password: {
        type: String,
        required: [true, 'Password is required'],
        validate: {
            validator: (value: string) => {
                return /^(?=.*[a-zA-Z])(?=.*[0-9])(?=.{8,256})/.test(value);
            },
            message: 'Wrong password format',
        },
    },
};

const userSchema = new mongoose.Schema(userSchemaDefinition, {
    timestamps: true,
});

export const User = mongoose.model('User', userSchema);
