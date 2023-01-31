import { IsAlphanumeric } from 'class-validator';

export class CreateProjectDto {
  @IsAlphanumeric()
  title: string;
}
