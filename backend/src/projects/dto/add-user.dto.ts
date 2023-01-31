import { IsHexadecimal, Length } from 'class-validator';
import { Rights } from '../enums/rights.enum';

export class AddUserDto {
  @IsHexadecimal()
  @Length(24)
  userId: string;
  rights: Rights[];
}
