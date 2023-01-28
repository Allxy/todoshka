import {
  Body,
  Controller,
  Get,
  HttpStatus,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common';
import { CurrentUser } from 'src/decorators/current-user.decorator';
import { AccessTokenGuard } from 'src/guards/acces-token.guard';
import { RefreshTokenGuard } from 'src/guards/refresh-token.guard';
import { CreateUserDto } from 'src/users/dto/create-user.dto';
import { User } from 'src/users/user.schema';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';

@Controller('/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/signup')
  async signUp(@Res() response, @Body() user: CreateUserDto) {
    const tokens = await this.authService.signUp(user);
    return response.status(HttpStatus.CREATED).json(tokens);
  }

  @Post('/signin')
  async signIn(@Res() response, @Body() user: AuthDto) {
    const token = await this.authService.signIn(user);
    return response.status(HttpStatus.OK).json(token);
  }

  @UseGuards(AccessTokenGuard)
  @Get('/logout')
  logout(@CurrentUser() user: User) {
    this.authService.logout(user['_id']);
  }

  @UseGuards(RefreshTokenGuard)
  @Get('/refresh')
  refreshTokens(@CurrentUser() user: User) {
    const userId = user['_id'];
    const refreshToken = user['refreshToken'];
    return this.authService.refreshTokens(userId, refreshToken);
  }
}
