import {
  Body,
  Controller,
  Get,
  HttpStatus,
  Post,
  Res,
  UseGuards,
} from '@nestjs/common';
import { CurrentUser } from 'src/auth/decorators/current-user.decorator';
import { User } from 'src/users/user.schema';
import { AuthService } from './auth.service';
import { SigninDto } from './dto/signin.dto';
import { SignupDto } from './dto/signup.dto';
import { RefreshTokenGuard } from './guards/refresh-token.guard';

@Controller('/auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/signup')
  async signUp(@Res() response, @Body() user: SignupDto) {
    const tokens = await this.authService.signUp(user);
    return response.status(HttpStatus.CREATED).json(tokens);
  }

  @Post('/signin')
  async signIn(@Res() response, @Body() user: SigninDto) {
    const token = await this.authService.signIn(user);
    return response.status(HttpStatus.OK).json(token);
  }

  @UseGuards(RefreshTokenGuard)
  @Get('/logout')
  logout(@CurrentUser() user: User) {
    const userId = user['_id'];
    const refreshToken = user['refreshToken'];
    this.authService.logout(userId, refreshToken);
  }

  @UseGuards(RefreshTokenGuard)
  @Get('/refresh')
  refreshTokens(@CurrentUser() user: User) {
    const userId = user['_id'];
    const refreshToken = user['refreshToken'];
    return this.authService.refreshTokens(userId, refreshToken);
  }
}
