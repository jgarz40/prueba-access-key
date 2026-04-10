import boto3
from botocore.exceptions import ClientError
import sys
 
AWS_ACCESS_KEY_ID = ""
AWS_SECRET_ACCESS_KEY = ""
AWS_SESSION_TOKEN = ""  
 
def get_boto3_client(service):
    """Devuelve un cliente boto3 usando claves si están configuradas, si no usa las del entorno."""
    if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY:
        return boto3.client(
            service,
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            aws_session_token=AWS_SESSION_TOKEN if AWS_SESSION_TOKEN else None
        )
    else:
        return boto3.client(service)
 
# Archivo de prueba para simular la explotación de un bucket abierto.
TEST_FILE_KEY = "test-file.txt"
# --- CONFIGURACIÓN DE LA SIMULACIÓN ---
SIMULATION_NAME = "AWS Cloud Security Posture Review"
AUTHORIZATION_SCOPE = "Infraestructura AWS propiedad 123456789012. Pruebas no destructivas de lectura únicamente."
# --------------------------------------
 
def display_banner():
    """Muestra un banner de inicio para la simulación controlada."""
    banner = f"""
============================================================
              {SIMULATION_NAME.upper()}
               SIMULACIÓN CONTROLADA
============================================================
  Fecha y Hora de Inicio:  [Current Date and Time]
  Alcance de la Prueba:  {AUTHORIZATION_SCOPE}
  Tipo de Prueba:        Escaneo de Configuraciones Erróneas
  Herramienta:           HackerAI Security Assistant Script
============================================================
ADVERTENCIA: ESTE SCRIPT ES PARA USO EXCLUSIVO EN ENTORNOS
AUTORIZADOS. SU USO EN INFRAESTRUCTURA DE TERCEROS SIN CONSENTIMIENTO
EXPLÍCITO CONSTITUYE UNA ACTIVIDAD ILEGAL.
============================================================
"""
    # Reemplazar la fecha y hora por la actual al ejecutar el script
    import datetime
    output_banner = banner.replace("[Current Date and Time]", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print(output_banner)
 
 
def check_s3_public_access_and_test_access():
    """Enumera buckets S3, verifica su configuración de acceso público y simula la descarga de un archivo de prueba."""
    print("--- 1. Verificación de Acceso Público en Buckets S3 y Prueba de Lectura ---\n")
    s3 = get_boto3_client('s3')
 
    try:
        response = s3.list_buckets()
        buckets = response.get('Buckets', [])
        
        if not buckets:
            print("Resultado: No se encontraron buckets S3 en la cuenta.")
            return
 
        print(f"Resultado: Encontrados {len(buckets)} buckets. Analizando accesibilidad:")
 
        for bucket in buckets:
            bucket_name = bucket['Name']
            is_public_blocked = True
            
            try:
                block_config = s3.get_public_access_block(Bucket=bucket_name)
 
                if not block_config['PublicAccessBlockConfiguration']['BlockPublicAcls'] or \
                   not block_config['PublicAccessBlockConfiguration']['IgnorePublicAcls'] or \
                   not block_config['PublicAccessBlockConfiguration']['BlockPublicPolicy'] or \
                   not block_config['PublicAccessBlockConfiguration']['RestrictPublicBuckets']:
                    is_public_blocked = False
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    is_public_blocked = False
                else:
                    is_public_blocked = False
 
            if is_public_blocked:
                print(f" [OK] {bucket_name} - Acceso público bloqueado (Configuración por defecto correcta)")
            else:
                print(f" [RIESGO] {bucket_name} - **Acceso público potencialmente abierto.**")
                
                # --- Lógica de Simulación de Explotación ---
                print(f"   --> Prueba de Concepto: Intentando obtener metadata del archivo '{TEST_FILE_KEY}'...")
                
                try:
                    s3.head_object(Bucket=bucket_name, Key=TEST_FILE_KEY)
                    print(f"   🚨🚨 **VULNERABILIDAD CRÍTICA:** Archivo '{TEST_FILE_KEY}' **PÚBLICO** y Accedido. Confirma un riesgo de exposición de datos.")
                except ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code == '404':
                        print(f"   [INFO] El archivo de prueba no fue encontrado (404). El bucket puede estar abierto, pero el archivo no existe o tiene otro nombre.")
                    elif error_code == '403':
                         print(f"   [SEGURO] Acceso Denegado (403): El archivo está protegido correctamente, incluso si la configuración general del bucket es débil.")
                    else:
                        print(f"   [FALLO] No se pudo acceder. Código de error: {error_code}.")
 
    except ClientError as e:
        print(f"Error grave al listar buckets: {e}. Revisa los permisos de la entidad IAM.")
    print("\n" + "="*70) # Separador visual
 
def check_iam_wildcard_policies():
    """Busca en todas las políticas IAM customizadas el permiso 'iam:*'."""
    print("--- 2. Verificación de Políticas IAM con Permisos de Escalada ('iam:*') ---\n")
    iam = get_boto3_client('iam')
    
    try:
        response = iam.list_policies(Scope='Local')
        policies = response.get('Policies', [])
        
        if not policies:
            print("Resultado: No se encontraron políticas IAM administradas por el cliente.")
            return
 
        high_risk_policies = []
        for policy in policies:
            policy_arn = policy['Arn']
            policy_name = policy['PolicyName']
            
            response_version = iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=policy['DefaultVersionId']
            )
            
            document = response_version['PolicyVersion']['Document']
            
            for statement in document.get('Statement', []):
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    
                    if isinstance(actions, str):
                        actions = [actions]
                        
                    for action in actions:
                        if action.lower() == 'iam:*' or action.lower() == '*':
                            # Sólo se añade una vez por política
                            if (policy_name, policy_arn) not in high_risk_policies:
                                high_risk_policies.append((policy_name, policy_arn))
                            break
                    
        if high_risk_policies:
            print("\n🚨🚨 **POLÍTICAS CON RIESGO DE ESCALADA ENCONTRADAS** (Violación PoLP):")
            for name, arn in high_risk_policies:
                print(f" [ALERTA] Nombre: {name} | ARN: {arn}")
        else:
            print(" [OK] No se encontraron políticas customizadas con 'iam:*' o '*' que permitan una escalada directa de privilegios en IAM.")
 
    except ClientError as e:
        print(f"Error grave al listar políticas IAM: {e}. Revisa los permisos de la entidad IAM.")
    print("\n" + "="*70) # Separador visual
 
def check_ec2_open_ports():
    """Busca grupos de seguridad EC2 que exponen puertos sensibles (22, 3389) a 0.0.0.0/0."""
    print("--- 3. Verificación de Grupos de Seguridad EC2 Abiertos a Internet (0.0.0.0/0) ---\n")
    ec2 = get_boto3_client('ec2')
    critical_ports = [22, 3389, 21, 23, 8080, 5432, 3306, 27017]
 
    try:
        response = ec2.describe_security_groups()
        security_groups = response.get('SecurityGroups', [])
 
        if not security_groups:
            print("Resultado: No se encontraron grupos de seguridad.")
            return
 
        at_risk_sgs = []
        for sg in security_groups:
            sg_id = sg['GroupId']
            sg_name = sg['GroupName']
            
            for rule in sg.get('IpPermissions', []):
                
                from_port = rule.get('FromPort')
                to_port = rule.get('ToPort')
                
                is_critical_port = (from_port in critical_ports) or \
                                   (from_port and to_port and any(p >= from_port and p <= to_port for p in critical_ports))
                
                if is_critical_port:
                    
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp')
                        
                        if cidr == '0.0.0.0/0':
                            port_range = f"{from_port}-{to_port}" if from_port != to_port and from_port is not None and to_port is not None else str(from_port) if from_port is not None else "All"
                            
                            # Asegurar que no haya duplicados si hay varias reglas 0.0.0.0/0 en el mismo SG
                            risk_description = f"Expone Puerto {port_range} ({rule.get('IpProtocol', 'All')}) a 0.0.0.0/0."
                            if (sg_id, risk_description) not in [(item['ID'], item['Description']) for item in at_risk_sgs]:
                                at_risk_sgs.append({
                                    'ID': sg_id,
                                    'Name': sg_name,
                                    'Description': risk_description
                                })
                            break
            
        if at_risk_sgs:
            print("\n🚨🚨 **GRUPOS DE SEGURIDAD ATACABLES ENCONTRADOS** (Riesgo de acceso a servicios):")
            for item in at_risk_sgs:
                print(f" [ALERTA] SG ID: {item['ID']} | Nombre: {item['Name']} | {item['Description']}")
        else:
            print(" [OK] No se encontraron grupos de seguridad que expongan puertos críticos a 0.0.0.0/0.")
 
    except ClientError as e:
        print(f"Error grave al describir grupos de seguridad: {e}. Revisa los permisos de la entidad IAM.")
    print("\n" + "="*70) # Separador visual
 
 
if __name__ == "__main__":
    display_banner()
    check_s3_public_access_and_test_access()
    check_iam_wildcard_policies()
    check_ec2_open_ports()
    print("\n*** FIN DE LA SIMULACIÓN CONTROLADA ***")
