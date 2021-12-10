import io
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
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

    def codificar64(self, msj):
        # Convertir la cadena en bytes
        mensaje_bytes = msj.encode('utf-8')
        # Codificar base64
        mensaje_base64 = base64.b64encode(mensaje_bytes)
        return mensaje_base64

    def cifrar_msj(self, pub_key, msj):
        # Cifrar el mensaje de Mark con la llave pública de Jeno

        # Instancia del cifrador asimétrico
        cipher_rsa = PKCS1_OAEP.new(pub_key)

        # Encriptamos la cadena usando la clave pública
        enc_data = cipher_rsa.encrypt(msj)

        return enc_data
        
    def saludar (self, name, msj):
        print("****Iniciar comunicación****")
        print("Hola, soy " + name)
        print("Este es mi mensaje: " + str(msj))
        mensaje_resp = "Hola " + name + " recibí tu mensaje: " + str(msj)
        self.responder(mensaje_resp)

    def responder(self, msj):
        print()
        print(str(msj) + " MensajeRespuesta")

    def descifrar_msj(self, msj):
        # Instancia del cifrador asimétrico
        cipher_rsa = PKCS1_OAEP.new(self.llave_priv)

        # Desencriptamos la cadena usando la clave privada
        dec_data = cipher_rsa.decrypt(msj)
        return dec_data

    def decodificar64(self, msj):
        # Decodificar base64
        mensaje_base_64 = base64.b64decode(msj)

        # Convertir los bytes en cadenas
        mensaje = mensaje_base_64.decode('utf-8')
        return mensaje
    
    def esperar_respuesta(self, msj):
        mensaje_desc = self.descifrar_msj(msj)
        mensaje_final = self.decodificar64(mensaje_desc)
        self.almacenar_msj(mensaje_final)

    def almacenar_msj(self, msj):
       
        mensaje = str(msj)
        tabla = "\n" + mensaje
        archivo = open("RegistroB.txt", "a+")
        archivo.write(str(tabla))
       
        archivo.close()

        for i, line in enumerate(open('RegistroB.txt').readlines()):
            #print(i, line)
            dicc = {}
            dicc[i] = line
            res = "ID: " + str(i)
            #return res
        
        archivo = open("Registro12.txt", "a+")
        tabla2 = "\n" + str(dicc)
        archivo.write(tabla2)
        
        archivo.close()
     

# Paso 1: las dos personas deben generar su par de llaves 
mark = ObjetoSeguro("Mark")
llav_publica, llav_priv = mark.gen_llaves()
print("Mark tu llave pública y tu llave privada están listas")
jeno = ObjetoSeguro("Jeno")
print("Jeno tu llave pública y tu llave privada están listas")
print()

# Paso 2: acceder a la llave pública de Mark y Jeno 
llave_publica_mark = mark.llave_publica()
print("La llave pública de Mark está disponible: " + str(llave_publica_mark))
llave_publica_jeno = jeno.llave_publica()
print("La llave pública de Jeno está disponible: " + str(llave_publica_jeno))
print()

# Paso 3: codificar el mensaje de Mark en base64
mensaje_codificado = mark.codificar64("Hola, ¿quieres ir al cine?")
print("El mensaje codificado base64 de Mark es: " + str(mensaje_codificado))

# Paso 4: cifrar el mensaje de Mark
mensaje_cifrado = mark.cifrar_msj(llave_publica_jeno, mensaje_codificado)
print("El mensaje de Mark ya está cifrado" )
print()

# Paso 5: enviar el nombre de Mark y su mensaje cifrado a Jeno
saludo = mark.saludar("Mark", mensaje_cifrado)
print()

# Paso 6: Jeno descifra el mensaje de Mark con su llave privada
mensaje_base64 = jeno.descifrar_msj(mensaje_cifrado)

# Paso 7: Decodificar el mensaje (base64 a cadena)
mensaje_claro = jeno.decodificar64(mensaje_base64)
print("Jeno descifra y decodifica el mensaje de Mark")
print("Mensaje obtenido: " + str(mensaje_claro))
print()

# Paso 8: Jeno envía su respuesta cifrada 
mensaje_codificado_j = jeno.codificar64("No, tengo que terminar mi tarea")
mensaje_cifrado_j = jeno.cifrar_msj(llave_publica_mark, mensaje_codificado_j)
print("Jeno envía su respuesta cifrada")
mark.esperar_respuesta(mensaje_cifrado_j)
print("Mark almacena la respuesta de Jeno")

# Paso 9: Mark envía su respuesta
mensaje_codificado_m = mark.codificar64("Está bien, yo también debería estudiar")
mensaje_cifrado_m = mark.cifrar_msj(llave_publica_jeno, mensaje_codificado_m)
print("Mark envía su respuesta cifrada")
jeno.esperar_respuesta(mensaje_cifrado_m)
print("Jeno almacena la respuesta")

