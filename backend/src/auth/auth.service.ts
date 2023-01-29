import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'src/users/users.service';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { BadRequestException } from '@nestjs/common';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { ForbiddenException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Auth, AuthDocument } from './auth.schema';
import { Model } from 'mongoose';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(Auth.name) private authModel: Model<AuthDocument>,
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async signUp(
    createUserDto: CreateUserDto,
  ): Promise<{ accessToken: string; refreshToken: string }> {
    const userExists = await this.usersService.findByEmail(createUserDto.email);
    if (userExists) {
      throw new BadRequestException('User already exists');
    }

    const hash = await this.hashData(createUserDto.password);
    const newUser = await this.usersService.create({
      ...createUserDto,
      password: hash,
    });
    const payload = {
      _id: newUser._id,
      email: newUser.email,
      roles: newUser.roles,
    };
    return await this.updateRefreshToken(newUser._id, payload);
  }

  async signIn(data: AuthDto) {
    const user = await this.usersService.findByEmail(data.email);
    if (!user) throw new BadRequestException('User does not exist');
    const passwordMatches = await bcrypt.compare(data.password, user.password);
    if (!passwordMatches)
      throw new BadRequestException('Password is incorrect');
    const payload = {
      _id: user._id,
      email: user.email,
      roles: user.roles,
    };
    return await this.updateRefreshToken(user._id, payload);
  }

  async logout(userId: string, refreshToken: string) {
    await this.authModel.findOneAndUpdate(
      { user: userId },
      { $pull: { refreshTokens: refreshToken } },
    );
  }

  async removeAllRefreshTokens(userId: string) {
    await this.authModel.findOneAndUpdate(
      { user: userId },
      { refreshTokens: [] },
    );
  }

  async refreshTokens(userId: string, refreshToken: string) {
    const auth = await this.authModel
      .findOne({ user: userId })
      .populate('user');
    if (!auth || !auth.refreshTokens.includes(refreshToken))
      throw new ForbiddenException('Access Denied');
    const payload = {
      _id: auth.user._id,
      email: auth.user.email,
      roles: auth.user.roles,
    };
    await this.logout(auth.user._id, refreshToken);
    return await this.updateRefreshToken(auth.user._id, payload);
  }

  async hashData(data: string) {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(data, salt);
  }

  async updateRefreshToken(userId: string, payload: any) {
    const tokens = await this.getTokens(payload);

    await this.authModel.updateOne(
      { user: userId },
      { $addToSet: { refreshTokens: tokens.refreshToken } },
      { upsert: true },
    );

    return tokens;
  }

  async getTokens(payload: any) {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
        expiresIn: '15m',
      }),
      this.jwtService.signAsync(payload, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: '7d',
      }),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }
}
