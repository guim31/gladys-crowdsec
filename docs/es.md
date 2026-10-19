# CrowdSec

[CrowdSec](https://www.crowdsec.net/) lee los registros de sus servidores (SSH,
servidor web, Home Assistant, Nextcloud…), reconoce los ataques con sus
escenarios (fuerza bruta, escaneos, exploits) y **bloquea** las direcciones
atacantes mediante sus bouncers (cortafuegos, proxy inverso). También comparte
lo que ve: cada instalación recibe la **lista de bloqueo de la comunidad**. Esta
integración lleva CrowdSec a Gladys: un dispositivo «CrowdSec» con las
decisiones activas y las alertas del día, escenas que se activan con cada nuevo
bloqueo o nueva alerta (para enviarse una notificación con la dirección y el
escenario), una acción que desbloquea una dirección y un widget del panel con
las últimas direcciones bloqueadas.

Probada con un CrowdSec v1.8.1 real (Docker, fuerza bruta SSH reproducida desde
un archivo de registro, decisiones añadidas y eliminadas con `cscli`).
Desarrollada sin una instalación en producción ni su lista de la comunidad: sus
comentarios son bienvenidos en
[las issues](https://github.com/guim31/gladys-crowdsec/issues).

## Lo que necesita

- Gladys Assistant 5.1.0 o posterior.
- CrowdSec 1.5 o posterior, con su **API local** (LAPI, puerto 8080) accesible
  desde la máquina de Gladys. Una instalación nativa solo escucha en
  `127.0.0.1:8080`: configure `listen_uri: 0.0.0.0:8080` bajo `api.server` en
  `/etc/crowdsec/config.yaml` (y mantenga el puerto 8080 cerrado hacia
  internet). La imagen Docker ya escucha en todas las interfaces: publique su
  puerto 8080.
- Una **clave de bouncer** (acceso de solo lectura a las decisiones).
- Opcional: una **cuenta de máquina** (usuario y contraseña) para leer las
  alertas y desbloquear una dirección.

La integración lee el flujo de decisiones de su clave de bouncer: la lista
completa al arrancar y una vez por hora, solo los cambios el resto del tiempo
(cada minuto por defecto). Con una cuenta de máquina, también lee las alertas
de la última hora. Nada sale a internet.

## Primeros pasos

### 1. Crear una clave de bouncer

En la máquina de CrowdSec:

```bash
cscli bouncers add gladys
```

Con Docker: `docker exec crowdsec cscli bouncers add gladys`. La clave solo se
muestra una vez: cópiela.

### 2. Crear una cuenta de máquina (opcional)

Para las alertas, el país de los atacantes y la acción de desbloqueo:

```bash
cscli machines add gladys --password 'una-contrasena-larga' -f /dev/null
```

`-f /dev/null` es importante: sin él, `cscli` escribe las nuevas credenciales
en lugar de las del agente local de CrowdSec.

### 3. Configurar la integración

En Gladys, **Integraciones → CrowdSec → Configuración**:

- **Dirección de la API local**: `http://192.168.1.2:8080` (la máquina de
  CrowdSec);
- **Clave de bouncer**: la clave del paso 1;
- **Usuario de máquina** y **Contraseña de máquina**: la cuenta del paso 2, o
  vacío;
- **Eliminar decisiones desde escenas**: desactivado por defecto, vea más
  abajo;
- **Intervalo de actualización**: de 30 segundos a 5 minutos;
- **Idioma de los nombres**: nombres de las funciones y resultados de escena.

**Probar la conexión** resume lo que lee la integración.

### 4. Añadir el dispositivo

En la pestaña **Descubrir**, añada el dispositivo «CrowdSec». El widget y los
desencadenantes de escena funcionan sin él.

## El dispositivo

El dispositivo «CrowdSec» tiene estas funciones:

| Función                        | Significado                                                                  |
| ------------------------------ | ---------------------------------------------------------------------------- |
| **Accesible**                  | 1 cuando la API local responde, 0 tras dos lecturas fallidas seguidas        |
| **Decisiones locales**         | Decisiones activas tomadas aquí: escenarios de CrowdSec, `cscli`, la consola |
| **Decisiones de la comunidad** | Decisiones activas de la lista de la comunidad y de las listas suscritas     |
| **Alertas (24 h)**             | Alertas iniciadas en las últimas 24 horas (solo con cuenta de máquina)       |
| **Último escenario**           | Escenario de la última alerta, o de la última decisión local                 |

Cada número conserva su historial, para un gráfico de los ataques a lo largo de
las semanas.

## Panel

El widget **Decisiones de CrowdSec** muestra las decisiones locales activas, la
lista de la comunidad y las alertas del día, y luego las últimas direcciones
bloqueadas: dirección o rango, escenario y tiempo restante, un icono rojo para
un bloqueo, naranja para un captcha. **Actualizar** vuelve a leer CrowdSec.

## Escenas

### Desencadenantes

- **Nueva decisión local**: CrowdSec bloquea una dirección (o le pide un
  captcha). El filtro conserva solo los bloqueos o solo los captchas.
  Variables: la dirección o el rango, el ámbito (`Ip`, `Range`), la remediación
  (`ban`, `captcha`), el escenario, el origen (`crowdsec` para un escenario,
  `cscli` para una decisión añadida a mano), la duración en minutos y el país
  del atacante cuando CrowdSec lo conoce (cuenta de máquina y enriquecimiento
  GeoIP).
- **Nueva alerta**: un escenario se activa sobre un origen (solo con cuenta de
  máquina), con o sin decisión (un escenario en modo simulación genera alertas
  sin bloquear). Variables: el escenario, la dirección de origen, el ámbito, el
  país, el operador de red, el número de eventos y de decisiones tomadas.

Un escenario que bloquea activa ambos desencadenantes: elija uno para sus
notificaciones. Las decisiones de la lista de la comunidad nunca activan nada:
llegan por decenas de miles. Cuando llegan más de 20 decisiones o alertas en
una lectura (un gran escaneo), solo las 20 más recientes activan una escena.

### Acciones

- **Estado de CrowdSec**: lee los contadores para las siguientes acciones —
  accesible o no, decisiones locales y de la comunidad, alertas de las últimas
  24 horas, la última dirección bloqueada, el último escenario — y una frase
  lista como «CrowdSec: 3 decisión(es) local(es), 15012 decisión(es) de la
  comunidad, 5 alerta(s) en 24 h (203.0.113.7, ssh-bf).»
- **Eliminar una decisión (desbloquear)**: elimina todas las decisiones sobre
  una dirección (`203.0.113.7`) o un rango (`203.0.113.0/24`), también las de
  la lista de la comunidad (vuelven en la siguiente descarga de la lista). El
  campo de dirección acepta las variables del desencadenante. **Desactivada por
  defecto**: active «Eliminar decisiones desde escenas» en la configuración,
  con una cuenta de máquina. Salidas: el número de decisiones eliminadas y una
  frase.

### Ideas de escenas

- **Nueva decisión local** → enviar un mensaje: «CrowdSec ha bloqueado
  {{triggerEvent.data.ip}} ({{triggerEvent.data.scenario}}, {{triggerEvent.data.country}})».
- Cada mañana, **Estado de CrowdSec** → enviar su frase: la noche de sus
  servidores en una línea.
- Cuando la función **Accesible** pasa a 0, enviar un mensaje: la protección de
  la casa ha caído.
- Un botón del panel que ejecuta **Eliminar una decisión (desbloquear)** sobre
  la dirección de un familiar bloqueado por error.

## Solución de problemas

- **«CrowdSec no responde»**: compruebe la dirección y el puerto desde la
  máquina de Gladys (`curl http://192.168.1.2:8080/health` responde
  `{"status":"up"}`) y el `listen_uri` de una instalación nativa.
- **«clave de bouncer rechazada»**: la clave se copió mal o se eliminó
  (`cscli bouncers list`); cree una nueva.
- **«usuario o contraseña de máquina rechazados: sin alertas»**: compruebe con
  `cscli machines list` que la máquina existe y está validada. Las decisiones
  se siguen leyendo.
- **«no hay API local de CrowdSec en esta dirección»**: la dirección lleva a
  otro servicio; la API local responde en el puerto 8080 por defecto.
- **«certificado rechazado»**: use la dirección `http://` en la red local, o un
  certificado reconocido por Gladys.
- **Sin país en las variables**: CrowdSec añade el país con el parser
  `crowdsecurity/geoip-enrich`, y solo a las alertas: hace falta la cuenta de
  máquina.
- Más detalles en los registros de la integración (Integraciones → CrowdSec →
  Registros). Las direcciones completas solo aparecen con `LOG_LEVEL=debug`.

## Limitaciones

- Una sola API local de CrowdSec por integración.
- Las decisiones sobre un país o un AS (ámbitos distintos de `Ip` y `Range`) no
  se cuentan: el flujo de un bouncer solo lleva direcciones y rangos.
- Las alertas requieren una cuenta de máquina: con la clave de bouncer sola, ni
  alertas ni país.
- Añadir una decisión (bloquear una dirección) no se ofrece: CrowdSec y `cscli`
  lo hacen mejor.
- La consola de CrowdSec (app.crowdsec.net) no se lee.
