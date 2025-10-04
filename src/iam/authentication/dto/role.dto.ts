import { IsEnum, IsNotEmpty } from 'class-validator';
import { Role } from '../../enums/role.enum';

export class RoleDto {
  @IsNotEmpty()
  userId: string;

  @IsEnum(Role)
  role: Role;
}
