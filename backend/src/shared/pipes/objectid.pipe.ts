import {
  PipeTransform,
  Injectable,
  ArgumentMetadata,
  BadRequestException,
} from '@nestjs/common';
import { isHexadecimal } from 'class-validator';

@Injectable()
export class ParseObjectIdPipe implements PipeTransform {
  transform(value: any, metadata: ArgumentMetadata) {
    if (!isHexadecimal(value) || value.toString().length !== 24)
      throw new BadRequestException('Not valid ObjectID');
    return value;
  }
}
