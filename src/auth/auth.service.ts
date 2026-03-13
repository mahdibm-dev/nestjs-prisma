import { Injectable } from '@nestjs/common';
import { PrismaService } from '@/prisma/prisma.service';
import { AuthDto } from './dto';
import argon from 'argon2';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    try {
      const hash = await argon.hash(dto.password);
      // save the new user in the db
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
        select: {
          id: true,
          email: true,
          createdAt: true,
          updatedAt: true,
        },
      });
      return user;
    } catch (error) {
      if (error?.code === 'P2002') {
        return { msg: 'Email already exists' };
      }
      throw error;
    }
  }

  async signin(dto: AuthDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) {
      return { msg: 'Credentials incorrect' };
    }
    const pwMatches = await argon.verify(user.hash, dto.password);
    if (!pwMatches) {
      return { msg: 'Credentials incorrect' };
    }
    const { hash, ...userWithoutHash } = user;
    return userWithoutHash;
  }
}
