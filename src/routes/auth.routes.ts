import { Router } from 'express';
import {
    refreshToken,
    register,
    login,
    logout,
    changePassword,
    validateRequest,
} from '../controllers/auth.controller';
import { verifyToken } from '../middleware/verifyToken';

const userRouter = Router();

userRouter.post('/register', [verifyToken], register);
userRouter.post('/login', login);
userRouter.delete('/logout', logout);

userRouter.patch('/change-password', [verifyToken], changePassword);
userRouter.get('/refresh', refreshToken);

userRouter.get('/auth', [verifyToken], validateRequest);

export default userRouter;
