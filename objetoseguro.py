from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

class ObjetoSeguro:
    def __init__(self, nombre):
        self.nombre = nombre 
        self.llave_pub, self.llave_priv = self.gen_llaves()
        
    def gen_llaves(self): 
        # Llave privada
        llave = RSA.generate(2048)
        # Llave pública
        llave_publica = llave.publickey()
        return llave_publica, llave

    def llave_publica(self):
        # Obtener la llave pública de la persona con la que se va a comunicar 
        return self.llave_pub

    def codificar64(self, msj:str):
        #print("Mensaje de " + self.nombre + ": "+ str(msj))
        # Convertir la cadena en bytes
        mensaje_bytes = msj.encode('utf-8')
        # Codificar base64
        mensaje_base64 = base64.b64encode(mensaje_bytes)
        return mensaje_base64

    def cifrar_msj(self, pub_key:str, msj:str):
        # Cifrar el mensaje del emisor con la llave pública del receptor
        # Instancia del cifrador asimétrico con la llave pública
        cifrador_rsa = PKCS1_OAEP.new(pub_key)
        # Cifrar el mensaje 
        msm_cifrado = cifrador_rsa.encrypt(msj)
        return msm_cifrado
        
    def saludar(self, name:str, msj:str):
        # El emisor saluda y empieza la comunicación
        # Se envía automáticamente la respuesta del receptor
        print("****Iniciar comunicación****")
        print("Hola, soy " + name)
        print("Este es mi mensaje: " + str(msj))
        print()
        mensaje_resp = "Hola " + name + " recibí tu mensaje: " + str(msj)
        self.responder(mensaje_resp)

    def responder(self, msj:str):
        # Concatenar el mensaje recibido con la respuesta 
        print(str(msj) + " MensajeRespuesta")

    def descifrar_msj(self, msj:bytes):
        # Instancia del cifrador asimétrico
        cifrador_rsa = PKCS1_OAEP.new(self.llave_priv)
        # Descifrar el mensaje usando la llave privada del receptor
        msm_descifrado = cifrador_rsa.decrypt(msj)
        return msm_descifrado

    def decodificar64(self, msj:bytes):
        # Decodificar base64
        mensaje_base_64 = base64.b64decode(msj)
        # Convertir los bytes en cadena
        mensaje_claro = mensaje_base_64.decode('utf-8')
        return mensaje_claro
    
    def esperar_respuesta(self, msj:bytes):
        # Recibe un mensaje de respuesta cifrado 
        mensaje_desc = self.descifrar_msj(msj)
        mensaje_final = self.decodificar64(mensaje_desc)
        # Almacenar el mensaje en claro en un archivo.txt 
        id = self.almacenar_msj(mensaje_final)
        return id
    
    def almacenar_msj(self, msj):
        # Escribir los mensajes 
        tabla = "\n" + str(msj)
        archivo = open("Mensajes.txt",'a+')
        archivo.write(str(tabla))
        archivo.close()

        # Enumerar los mensajes
        archivo = "Mensajes.txt"
        salida = "Registro_mensajes.txt"
        lineas_escribir = []
        with open(archivo, "r") as archivo_lectura:
            numero_linea = 0
            for linea in archivo_lectura:
                numero_linea += 1
                linea = linea.rstrip()
                lineas_escribir.append(str(numero_linea) + " - " + linea)

        with open(salida, "w") as archivo_salida:
            for linea in lineas_escribir:
                archivo_salida.write(linea + "\n")
                msm = "ID: " + str(numero_linea)
        return msm
                
    def consultar_msj(self, id):
        # Retornar el mensaje que corresponda al id ingresado
        archivo = "Registro_mensajes.txt"
        lineas_escribir = []
        with open(archivo, "r") as archivo_lectura:
            numero_linea = 0
            for linea in archivo_lectura:
                numero_linea += 1
                linea = linea.rstrip()
                separado = linea.split(" ")
                if str(id) in separado:
                    lineas_escribir.append(linea)
        return lineas_escribir