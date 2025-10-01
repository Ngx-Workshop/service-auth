import { IsEnum, IsNotEmpty } from 'class-validator';
import { Role } from '../../enums/role.enum';

export class RoleDto {
  @IsNotEmpty()
  id: string;

  @IsEnum(Role)
  role: Role;
}
