from objetoseguro import ObjetoSeguro

if __name__ == '__main__':
    # ************PROCESO DE COMUNICACIÓN MARK-JENO*******

    # Paso 1: las dos personas deben generar su par de llaves 
    mark = ObjetoSeguro("Mark")
    jeno = ObjetoSeguro("Jeno")

    # Paso 2: Mark le pide a Jeno su llave pública 
    llave_publica_jeno = jeno.llave_publica()
   
    # Paso 3: codificar el mensaje de Mark en base64
    mensaje_codificado = mark.codificar64("Hola, ¿quieres ir al cine?")
   
    # Paso 4: cifrar el mensaje de Mark
    mensaje_cifrado = mark.cifrar_msj(llave_publica_jeno, mensaje_codificado)

    # Paso 5: enviar saludo con el nombre de Mark y su mensaje cifrado
    mark.saludar("Mark", mensaje_cifrado)

    # Paso 6: Jeno le pide a Mark su llave pública 
    llave_publica_mark = mark.llave_publica()
    
    # Paso 7: Jeno descifra el mensaje de Mark con su llave privada
    mensaje_base64 = jeno.descifrar_msj(mensaje_cifrado)

    # Paso 7: Decodifica el mensaje de Mark (base64 a cadena)
    mensaje_claro = jeno.decodificar64(mensaje_base64)
    print()
    print("Mensaje recibido por Jeno: " + str(mensaje_claro))
    print()

    # ************PROCESO DE COMUNICACIÓN JENO-MARK*******
    
    # Paso 8: Jeno cifra su mensaje y se lo envía a Mark junto con su nombre
    mensaje_codificado_j = jeno.codificar64("No, tengo que terminar mi tarea")
    mensaje_cifrado_j = jeno.cifrar_msj(llave_publica_mark, mensaje_codificado_j)
    jeno.saludar("Jeno", mensaje_cifrado_j)
    
     # Paso 7: Mark descifra el mensaje de Jeno con su llave privada
    msm_base64 = mark.descifrar_msj(mensaje_cifrado_j)

    # Paso 7: Decodifica el mensaje de Jeno (base64 a cadena)
    msm_claro = mark.decodificar64(msm_base64)
    print()
    print("Mensaje recibido por Mark: " + str(msm_claro))
    print()
   
    # Paso 9: Mark envía su respuesta
    mensaje_codificado_m = mark.codificar64("Está bien, yo también debería estudiar")
    mensaje_cifrado_m = mark.cifrar_msj(llave_publica_jeno, mensaje_codificado_m)

    # ************ALMACENAR Y ACCEDER A LOS MENSAJES********************

    # Jeno almacena el mensaje de Mark en texto claro
    id_msm_jeno = jeno.esperar_respuesta(mensaje_cifrado)
    print("ID del mensaje que recibió Jeno: " + str(id_msm_jeno))

    # Mark almacena el mensaje de Jeno en texto claro
    id_msm_mark = mark.esperar_respuesta(mensaje_cifrado_j)
    print("ID del mensaje que recibió Mark: " + str(id_msm_mark))

    res_busqueda = mark.consultar_msj(2)
    print("Resultado de la búsqueda: " + str(res_busqueda))