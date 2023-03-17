import express, { request, response } from "express";
import users from "./database"
import { v4 as uuidv4 } from 'uuid'
import { hash, compare } from 'bcryptjs'
import jwt from 'jsonwebtoken'
import 'dotenv/config'


const app = express()

app.use(express.json())

//MIDDLEWARES -> São funções que ficam entre o cliente e o controller, e podem fazer uma lógica ou verificação que estava repetitiva nos services

    const inspectTokenMiddlewares = (request,response,next) => {
    let authorization = request.headers.authorization
   
    if(!authorization){
        return response.status(401).json({message:"Missing authorization headers"})
    }

    authorization = authorization.split(" ")[1]

    return jwt.verify(authorization,process.env.SECRET_KEY,(error,decoded) => {
        
        if(error){
            return response.status(401).json({
                message: 'Invalid token'
            })
        }

        request.user = {
            isAdm: decoded.isAdm,
            uuid: decoded.uuid
        }

        return next()
    })
    }

    const inspectIsAdmMiddlewares = (request,response,next) => {
    const user = request.user
    if(!user.isAdm){
        return response.status(403).json({message:"Missing admin permission"})
    }

    next()
    }
    
    const verifyOwnerMiddlewares = ({user,params},response,next) => {
        const {isAdm,uuid} = user
        const {id} = params 
        if(!isAdm && uuid !== id){
            return response.status(403).json({message:"Missing admin permission"})
        }

        next()
    }

// SERVICES -> Cuida da lógica de negócio e da manipulação de dados
    const createUserServices = async (body) => {

        const userAlreadyExists = users.find(element => element.email === body.email)

        if(userAlreadyExists){
            return [409,{message: "E-mail already registered"}]
        }

        const userData = {
            uuid: uuidv4(),
            createdOn: new Date(),
            updatedOn: new Date(),
            ...body,
            password: await hash(body.password,10),
        }

        const {password,...rest} = userData

        users.push(userData)

        return [201,rest]
    }

    const createSessionServices = async ({email,password}) => {
        const user = users.find(element => element.email === email)

        if(!user){
            return [401,{message:"Wrong email/password"}]
        }

        const passwordMatch = await compare(password, user.password)

        if(!passwordMatch){
            return [401,{message:"Wrong email/password"}]
        }

        const token = jwt.sign(
            {
                isAdm : user.isAdm,
                uuid: user.uuid
            },
            process.env.SECRET_KEY,
            {
             expiresIn:"24h",
            }
            )

        return [200,{token}]
    }

    const fetchUserServices = (id) => {
        const userData = users.find(element => element.uuid === id)
        
        const{password, ...rest} = userData

        return [201,rest]
    }

    const updatedUserServices = async (id,userData) => {
        
        let index = users.findIndex(element => element.uuid === id)
        
        userData.password?
        (userData.password = await hash(users[index].password,10))    
        :
        (userData.password = users[index].password)
                          
        users[index] = {...users[index],...userData}
        const {password,...rest} = users[index]
    
            return [200,rest]
      
    }

    const deleteUserServices = (id) => {
       
            const index = users.findIndex(element => element.uuid === id)
            users.splice(index,1)
            return [204,{}]
      
    }

// CONTROLLERS -> Recebem os dados da requisição do cliente, e retornam uma resposta para o cliente
    const createUserControllers = async (request,response) => {
        const [status,data] = await createUserServices(request.body)
        return response.status(status).json(data)
    }

    const createSessionControllers = async (request,response) => {
        const [status,data] = await createSessionServices(request.body)
        return response.status(status).json(data)
    }

    const listUsersControllers = (request,response) => {
        return response.json(users)
    }

    const fetchUserControllers = (request,response) => {
        const [status,user] = fetchUserServices(request.user.uuid)
        return response.status(status).json(user)
    }

    const updatedUserControllers = async (request,response) => {
        const [status,user] = await updatedUserServices(request.params.id,request.body)
        return response.status(status).json(user)
    }

    const deleteUserControllers = (request,response) => {
        const [status,data] = deleteUserServices(request.params.id)
        return response.status(status).json(data)
    }

// ROTAS

app.post("/users",createUserControllers)
app.post("/login",createSessionControllers)
app.get("/users", inspectTokenMiddlewares,inspectIsAdmMiddlewares,listUsersControllers)
app.get("/users/profile",inspectTokenMiddlewares,fetchUserControllers)
app.patch("/users/:id",inspectTokenMiddlewares,verifyOwnerMiddlewares,updatedUserControllers)
app.delete("/users/:id",inspectTokenMiddlewares,verifyOwnerMiddlewares,deleteUserControllers)

app.listen("3003", () => {
    console.log("Server running in port 3003")
})

export default app