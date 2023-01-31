import { ArgumentMetadata, Injectable, PipeTransform } from '@nestjs/common';
import { ParseObjectIdPipe } from 'src/shared/pipes/objectid.pipe';
import { UsersService } from '../users.service';

@Injectable()
export class UserByIdPipe
  extends ParseObjectIdPipe
  implements PipeTransform<string>
{
  constructor(private readonly usersService: UsersService) {
    super();
  }

  async transform(value: string, metadata: ArgumentMetadata) {
    super.transform(value, metadata);
    return await this.usersService.findById(value);
  }
}
