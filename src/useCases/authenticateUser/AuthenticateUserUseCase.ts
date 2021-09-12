import { compare } from "bcrypt";
import { client } from "../../prisma/client"
import { sign } from 'jsonwebtoken'

interface IRequest {
    username: string;
    password: string;
}

class AuthenticateUserUseCase {
    async execute({ username, password }: IRequest) {
        const userAlreadyExists = await client.user.findFirst({
            where: {
                username
            }
        })

        if (!userAlreadyExists) {
            throw new Error("User or password incorrect!");
        }

        const passwordMatch = await compare(password, userAlreadyExists.password)

        if (!passwordMatch) {
            throw new Error("User or password incorrect!");
        }

        const token = sign({}, "3f70b5ad-5907-4fa2-8599-f6fbb73f3063", {
            subject: userAlreadyExists.id,
            expiresIn: "20s"
        })

        return { token }
    }
}

export { AuthenticateUserUseCase }