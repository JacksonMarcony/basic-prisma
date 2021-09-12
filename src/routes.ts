import { Router } from "express"
import { AuthenticateUserController } from "./useCases/authenticateUser/AuthenticateUserController"
import { CreateUserController } from "./useCases/createUser/CreateUserController"

const router = Router()

const createUserController = new CreateUserController()
const authenticateUserController = new AuthenticateUserController()

router.post('/users', createUserController.handle)
router.post('/login', authenticateUserController.handle)

export { router }