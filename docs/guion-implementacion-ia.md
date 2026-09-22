# Qué hace la inteligencia artificial en nuestro proyecto

Seminario de Seguridad de la Información · 2026-2, Grupo 3 · 2026-09-22

---

Voy a explicar qué papel cumple la inteligencia artificial en nuestro detector
de phishing, y por qué creemos que eso lo pone por encima de un detector
tradicional.

## El problema con los detectores normales

Un detector de phishing clásico funciona con reglas. Mira si el correo trae un
enlace acortado, si el texto del enlace apunta a un sitio distinto del que
muestra, si el dominio del remitente se parece a una marca conocida, si el
mensaje tiene errores de ortografía, si viene de un dominio recién registrado.
Cada cosa que encuentra suma puntos, y si el total pasa un umbral, marca el
correo.

Eso funciona muy bien contra el phishing masivo, el que se manda a un millón de
personas a ver quién cae. Pero tiene un límite claro: **solo detecta lo que
alguien programó como sospechoso de antemano**.

Y ahí está el problema que nos interesa. Hoy un atacante puede redactar un
correo con ayuda de una IA, y le sale un texto sin una sola falta de ortografía,
con tono corporativo perfecto, mandado desde un dominio que él mismo registró y
configuró bien, con SPF y DKIM pasando sin problema. Ese correo no dispara casi
ninguna regla. Nosotros lo comprobamos: nuestro propio detector de reglas le da
un puntaje por debajo del umbral y lo deja pasar.

Para las reglas ese correo es limpio. Para una persona que lo lee, no lo es.

## Qué le pedimos a la IA

Ahí es donde entra el modelo de lenguaje. Le pedimos una cosa que las reglas no
saben hacer: **juzgar la historia que cuenta el correo**.

Es decir, no le preguntamos cuántos enlaces hay ni si SPF pasó. Le preguntamos
si el pretexto tiene sentido. ¿Es normal que Recursos Humanos me escriba un
viernes a las 6 de la tarde para que actualice mis datos bancarios por un
formulario externo? ¿Es normal que el gerente me pida una transferencia urgente
y me diga que no lo comente con nadie? ¿Encaja el tono con quien dice ser?

Eso es exactamente lo que hace que una persona desconfíe de un correo, y es
justo lo que un sistema de reglas no puede representar. No es una lista de
palabras sospechosas: es entender la situación.

## Cómo lo conectamos

Nosotros no le entregamos el correo al modelo y esperamos a ver qué dice. El
flujo es así:

Primero nuestro código extrae todo lo que se puede verificar: los enlaces, el
dominio real de cada uno, el remitente, si hay cabeceras de autenticación y qué
dicen, los adjuntos. Eso es trabajo determinista y lo hacemos nosotros, porque
se puede probar y porque un modelo podría equivocarse ahí sin que nadie lo note.

Después le pasamos al modelo esas señales ya verificadas, junto con el correo, y
le pedimos su juicio sobre el pretexto. Le exigimos que responda en un formato
fijo: un número de riesgo entre 0 y 1, una explicación corta en español, y la
lista de indicadores en los que se basó.

Y por último combinamos las dos opiniones. El puntaje final es 60% del modelo y
40% de las reglas. Aparte medimos qué tanto coinciden: si las dos fuentes dicen
lo mismo, tenemos confianza alta; si una dice que está limpio y la otra que es
un ataque, el sistema lo marca como caso dudoso y lo manda a revisión de una
persona, en vez de inventarse una respuesta.

## En qué nos pone por encima

Tres cosas concretas.

**Detectamos ataques que no traen ninguna señal técnica.** El fraude del CEO
suele ser un correo corto, sin enlaces, sin adjuntos y sin nada raro en las
cabeceras. Para un detector de reglas es un correo normal. Para el modelo es una
petición financiera urgente con presión de autoridad y pedido de
confidencialidad, que es un patrón de ataque conocido.

**Explicamos el veredicto en lenguaje humano.** Un detector tradicional te dice
"puntaje 0.78, reglas disparadas: url_acortador, dominio_nuevo". El nuestro te
dice por qué el mensaje es sospechoso, en una frase que se entiende, y te
muestra las señales en las que se apoyó. Para alguien que tiene que decidir si
le cree al correo, eso vale más que el número.

**No dependemos de que alguien actualice una lista.** Cuando aparece un pretexto
nuevo, un detector de reglas necesita que un analista lo estudie, escriba la
regla y la despliegue. El modelo puede reconocer que la historia no cuadra sin
que nadie le haya enseñado ese ataque en particular.

## Lo que decidimos no dejarle hacer

Esto es igual de importante, porque el modelo también es un riesgo.

El correo que analizamos lo escribió el atacante, así que puede traer texto
dirigido al propio clasificador: instrucciones escondidas para que responda que
el mensaje es legítimo. Por eso el modelo nunca decide solo. Su peso está topado
en 60%, su respuesta está limitada a un formato cerrado del que no se puede
salir, y si detecta que están intentando manipularlo, eso no se ignora: se
reporta como un indicador más. Un correo que intenta engañar al detector nos
parece más sospechoso, no menos.

Tampoco le dejamos calcular nada ni visitar enlaces. Todo lo que sea verificable
lo hace nuestro código, que es auditable y se puede probar.

## En qué punto estamos

El sistema completo ya funciona de principio a fin, pero hoy detrás de esa
interfaz hay un componente de sustitución determinista, no un modelo real. Está
marcado en cada respuesta y se avisa en la pantalla. El siguiente paso es
conectar el modelo de verdad y medir, sobre corpus públicos, cuánto mejora
frente a nuestro propio detector de reglas.

Hasta que eso esté medido, lo que tenemos es la arquitectura y la hipótesis, no
el resultado.
