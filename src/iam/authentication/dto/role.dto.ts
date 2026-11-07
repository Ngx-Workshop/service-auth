import { IsEnum, IsNotEmpty, IsMongoId } from 'class-validator';
import { Role } from '../../enums/role.enum';

export class RoleDto {
  @IsNotEmpty()
  @IsMongoId()
  userId: string;

  @IsEnum(Role)
  role: Role;
}
