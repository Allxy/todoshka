import { IsEmail, IsAlpha, IsNotEmpty } from 'class-validator';

export class SignupDto {
  @IsAlpha()
  firstname: string;
  @IsAlpha()
  lastname: string;
  @IsEmail()
  email: string;
  @IsNotEmpty()
  password: string;
}
