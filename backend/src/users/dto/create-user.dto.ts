import { IsEmail, IsAlpha, IsNotEmpty } from 'class-validator';

export class CreateUserDto {
  @IsAlpha()
  firstname: string;
  @IsAlpha()
  lastname: string;
  @IsEmail()
  email: string;
  @IsNotEmpty()
  password: string;
  refreshToken?: string;
}
