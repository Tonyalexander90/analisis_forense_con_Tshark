
#!/usr/bin/env python3
"""
ANÁLISIS FORENSE COMPLETO CON TSHARK - INCIDENTE PHISHING AUSTRALIA
Script completo para análisis forense de PCAP usando tshark
"""

import subprocess
import sys
import re
import json
import os
from datetime import datetime
from collections import defaultdict, Counter

class ForensicAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.results = {
            'emails_compromised': set(),
            'suspicious_domains': set(),
            'phishing_urls': set(),
            'malicious_ips': set(),
            'http_requests': [],
            'dns_queries': set(),
            'post_data': [],
            'statistics': defaultdict(int)
        }
        
    def run_tshark_command(self, command, description=""):
        """Ejecuta comando tshark con manejo robusto de errores"""
        if description:
            print(f"🔍 {description}...")
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=60,
                encoding='utf-8',
                errors='ignore'
            )
            
            if result.returncode == 0:
                output_lines = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                return output_lines
            else:
                if "permission" in result.stderr.lower():
                    print(f"   ⚠️  Error de permisos. Ejecuta con sudo o como root")
                else:
                    print(f"   ⚠️  Error tshark: {result.stderr[:100]}...")
                return []
                
        except subprocess.TimeoutExpired:
            print(f"   ⏰ Timeout en comando")
            return []
        except Exception as e:
            print(f"   ❌ Error inesperado: {e}")
            return []

    def check_tshark_availability(self):
        """Verifica si tshark está disponible"""
        print("🔧 Verificando tshark...")
        try:
            result = subprocess.run(
                "tshark --version",
                shell=True,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                version_line = result.stdout.split('\n')[0] if result.stdout else "Desconocida"
                print(f"✅ tshark disponible: {version_line}")
                return True
            else:
                print("❌ tshark no está instalado")
                print("💡 Instala con: sudo apt install tshark")
                return False
        except Exception as e:
            print(f"❌ Error verificando tshark: {e}")
            return False

    def extract_basic_info(self):
        """Extrae información básica del archivo pcap"""
        print("\n📁 INFORMACIÓN BÁSICA DEL PCAP")
        print("=" * 40)
        
        # Información del archivo
        file_size = os.path.getsize(self.pcap_file)
        print(f"📏 Tamaño: {file_size / (1024*1024):.2f} MB")
        
        # Contar paquetes totales
        cmd = f'tshark -r "{self.pcap_file}" | wc -l'
        total_packets = self.run_tshark_command(cmd, "Contando paquetes")
        if total_packets:
            print(f"📦 Paquetes totales: {total_packets[0]}")
            self.results['statistics']['total_packets'] = int(total_packets[0])

    def analyze_http_traffic(self):
        """Analiza tráfico HTTP en busca de phishing"""
        print("\n🌐 ANÁLISIS DE TRÁFICO HTTP")
        print("=" * 40)
        
        # 1. Todas las solicitudes HTTP
        cmd = f'tshark -r "{self.pcap_file}" -Y "http.request" -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri'
        http_requests = self.run_tshark_command(cmd, "Extrayendo solicitudes HTTP")
        self.results['statistics']['http_requests'] = len(http_requests)
        
        for request in http_requests:
            fields = request.split('\t')
            if len(fields) >= 4:
                request_info = {
                    'src_ip': fields[0],
                    'dst_ip': fields[1],
                    'host': fields[2],
                    'uri': fields[3]
                }
                self.results['http_requests'].append(request_info)
                
                # Detectar phishing
                self._detect_phishing_patterns(request_info)

        # 2. Datos POST (credenciales)
        cmd = f'tshark -r "{self.pcap_file}" -Y "http.request.method == POST" -T fields -e http.host -e http.request.uri -e http.file_data'
        post_requests = self.run_tshark_command(cmd, "Analizando datos POST")
        self.results['statistics']['post_requests'] = len(post_requests)
        
        for post in post_requests:
            fields = post.split('\t')
            if len(fields) >= 3:
                post_data = {
                    'host': fields[0],
                    'uri': fields[1],
                    'data': fields[2]
                }
                self.results['post_data'].append(post_data)
                self._extract_credentials(post_data)

    def _detect_phishing_patterns(self, request_info):
        """Detecta patrones de phishing en solicitudes HTTP"""
        phishing_indicators = [
            'office365', 'microsoft', 'login', 'auth', 'credential',
            'password', 'signin', 'verification', 'account', 'security'
        ]
        
        host = request_info['host'].lower()
        uri = request_info['uri'].lower()
        
        for indicator in phishing_indicators:
            if indicator in host or indicator in uri:
                # Excluir dominios legítimos
                if not any(legit in host for legit in ['microsoft.com', 'office.com', 'live.com']):
                    self.results['suspicious_domains'].add(request_info['host'])
                    self.results['phishing_urls'].add(f"http://{request_info['host']}{request_info['uri']}")
                    self.results['malicious_ips'].add(request_info['dst_ip'])

    def _extract_credentials(self, post_data):
        """Extrae credenciales de datos POST"""
        data = post_data['data']
        
        # Buscar emails
        email_pattern = r'[a-zA-Z0-9._%+-]+@invent\.com'
        emails = re.findall(email_pattern, data, re.IGNORECASE)
        for email in emails:
            self.results['emails_compromised'].add(email)
        
        # Buscar parámetros de login
        login_params = ['email=', 'username=', 'user=', 'login=', 'password=', 'pass=', 'pwd=']
        for param in login_params:
            if param in data.lower():
                print(f"   🔑 Parámetro de login encontrado: {param}")

    def analyze_dns_traffic(self):
        """Analiza tráfico DNS en busca de dominios maliciosos"""
        print("\n🔍 ANÁLISIS DE TRÁFICO DNS")
        print("=" * 40)
        
        # Consultas DNS sospechosas
        cmd = f'tshark -r "{self.pcap_file}" -Y "dns" -T fields -e dns.qry.name'
        dns_queries = self.run_tshark_command(cmd, "Extrayendo consultas DNS")
        self.results['statistics']['dns_queries'] = len(dns_queries)
        
        phishing_keywords = ['office365', 'microsoft', 'login', 'auth', 'verify']
        
        for query in dns_queries:
            self.results['dns_queries'].add(query)
            query_lower = query.lower()
            
            # Buscar consultas de phishing
            for keyword in phishing_keywords:
                if keyword in query_lower:
                    if not any(legit in query_lower for legit in ['microsoft.com', 'office.com']):
                        self.results['suspicious_domains'].add(query)
                        print(f"   🚩 DNS sospechoso: {query}")

    def analyze_ssl_traffic(self):
        """Analiza tráfico SSL/TLS"""
        print("\n🔒 ANÁLISIS DE TRÁFICO SSL/TLS")
        print("=" * 40)
        
        # Handshakes SSL
        cmd = f'tshark -r "{self.pcap_file}" -Y "ssl.handshake" -T fields -e ip.src -e ip.dst -e ssl.handshake.extensions_server_name'
        ssl_connections = self.run_tshark_command(cmd, "Analizando handshakes SSL")
        
        for conn in ssl_connections:
            fields = conn.split('\t')
            if len(fields) >= 3 and fields[2]:
                server_name = fields[2]
                if any(keyword in server_name.lower() for keyword in ['office365', 'microsoft', 'login']):
                    if not any(legit in server_name for legit in ['microsoft.com', 'office.com']):
                        self.results['suspicious_domains'].add(server_name)

    def comprehensive_analysis(self):
        """Ejecuta análisis completo"""
        print("🕵️  INICIANDO ANÁLISIS FORENSE COMPLETO")
        print("=" * 50)
        print(f"Archivo: {self.pcap_file}")
        print(f"Hora de análisis: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)
        
        # Verificar tshark
        if not self.check_tshark_availability():
            return False
        
        # Ejecutar todos los análisis
        self.extract_basic_info()
        self.analyze_http_traffic()
        self.analyze_dns_traffic()
        self.analyze_ssl_traffic()
        
        return True

    def generate_report(self):
        """Genera reporte forense completo"""
        print("\n" + "="*70)
        print("📊 INFORME FORENSE COMPLETO - INCIDENTE PHISHING AUSTRALIA")
        print("="*70)
        
        # Estadísticas
        print(f"\n📈 ESTADÍSTICAS GENERALES:")
        for key, value in self.results['statistics'].items():
            print(f"   • {key.replace('_', ' ').title()}: {value}")
        
        # Usuarios afectados
        print(f"\n🔴 USUARIOS COMPROMETIDOS ({len(self.results['emails_compromised'])}):")
        if self.results['emails_compromised']:
            for i, email in enumerate(sorted(self.results['emails_compromised']), 1):
                print(f"   {i:2d}. {email}")
        else:
            print("   ✅ No se encontraron usuarios comprometidos")
        
        # Dominios sospechosos
        print(f"\n🌐 DOMINIOS DE PHISHING ({len(self.results['suspicious_domains'])}):")
        if self.results['suspicious_domains']:
            for domain in sorted(self.results['suspicious_domains']):
                print(f"   🚩 {domain}")
        
        # URLs maliciosas
        print(f"\n🔗 URLs DE PHISHING ({len(self.results['phishing_urls'])}):")
        if self.results['phishing_urls']:
            for url in sorted(self.results['phishing_urls'])[:10]:  # Mostrar primeras 10
                print(f"   🔗 {url}")
        
        # IPs maliciosas
        print(f"\n⚡ IPs MALICIOSAS ({len(self.results['malicious_ips'])}):")
        if self.results['malicious_ips']:
            for ip in sorted(self.results['malicious_ips']):
                print(f"   📍 {ip}")
        
        # Ejemplos de tráfico malicioso
        print(f"\n📋 EJEMPLOS DE ACTIVIDAD MALICIOSA:")
        examples_shown = 0
        for request in self.results['http_requests']:
            if any(domain in request['host'] for domain in self.results['suspicious_domains']):
                print(f"   📝 {request['src_ip']} -> {request['host']}{request['uri'][:50]}...")
                examples_shown += 1
                if examples_shown >= 3:
                    break
        
        if examples_shown == 0:
            print("   ℹ️  No se encontraron ejemplos claros de actividad maliciosa")

    def generate_recommendations(self):
        """Genera recomendaciones de seguridad"""
        print(f"\n🛡️  RECOMENDACIONES DE SEGURIDAD")
        print("=" * 40)
        
        total_affected = len(self.results['emails_compromised'])
        
        if total_affected > 0:
            print(f"🚨 ACCIONES CRÍTICAS REQUERIDAS:")
            print(f"   1. 🔐 RESETEO INMEDIATO de {total_affected} contraseñas")
            print(f"   2. 📧 NOTIFICACIÓN a usuarios afectados")
            print(f"   3. 🚫 BLOQUEO de {len(self.results['suspicious_domains'])} dominios maliciosos")
            print(f"   4. 🔒 IMPLEMENTACIÓN URGENTE de 2FA")
        else:
            print(f"✅ ACCIONES PREVENTIVAS:")
            print(f"   1. 🔒 IMPLEMENTAR 2FA para todos los usuarios")
            print(f"   2. 🚫 BLOQUEAR {len(self.results['suspicious_domains'])} dominios sospechosos")
            print(f"   3. 📚 CAPACITACIÓN en identificación de phishing")
        
        print(f"\n🔧 MEDIDAS TÉCNICAS:")
        print(f"   • Bloquear {len(self.results['malicious_ips'])} IPs maliciosas en firewall")
        print(f"   • Implementar filtrado URL avanzado")
        print(f"   • Monitorizar tráfico a dominios sospechosos")
        print(f"   • Revisar logs de acceso de usuarios potencialmente afectados")

    def export_results(self):
        """Exporta resultados a archivos"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Exportar usuarios afectados
        if self.results['emails_compromised']:
            with open(f'usuarios_afectados_{timestamp}.txt', 'w') as f:
                f.write("USUARIOS AFECTADOS - INCIDENTE PHISHING\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Total usuarios comprometidos: {len(self.results['emails_compromised'])}\n\n")
                for email in sorted(self.results['emails_compromised']):
                    f.write(f"{email}\n")
            print(f"💾 Usuarios afectados exportados: usuarios_afectados_{timestamp}.txt")
        
        # Exportar dominios a bloquear
        if self.results['suspicious_domains']:
            with open(f'dominios_bloquear_{timestamp}.txt', 'w') as f:
                f.write("DOMINIOS A BLOQUEAR - INCIDENTE PHISHING\n")
                f.write("=" * 50 + "\n\n")
                for domain in sorted(self.results['suspicious_domains']):
                    f.write(f"{domain}\n")
            print(f"💾 Dominios a bloquear exportados: dominios_bloquear_{timestamp}.txt")
        
        # Exportar reporte JSON
        report_data = {
            'analysis_date': datetime.now().isoformat(),
            'pcap_file': self.pcap_file,
            'statistics': dict(self.results['statistics']),
            'compromised_emails': sorted(list(self.results['emails_compromised'])),
            'suspicious_domains': sorted(list(self.results['suspicious_domains'])),
            'malicious_ips': sorted(list(self.results['malicious_ips'])),
            'phishing_urls': sorted(list(self.results['phishing_urls']))[:100]  # Limitar a 100 URLs
        }
        
        with open(f'reporte_forense_{timestamp}.json', 'w') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        print(f"💾 Reporte completo exportado: reporte_forense_{timestamp}.json")

def main():
    if len(sys.argv) != 2:
        print("Uso: python3 analisis_tshark.py archivo.pcap")
        print("Ejemplo: python3 analisis_tshark.py australia.pcap")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    if not os.path.exists(pcap_file):
        print(f"❌ Error: El archivo {pcap_file} no existe")
        sys.exit(1)
    
    # Crear analizador y ejecutar análisis
    analyzer = ForensicAnalyzer(pcap_file)
    
    if analyzer.comprehensive_analysis():
        analyzer.generate_report()
        analyzer.generate_recommendations()
        analyzer.export_results()
        
        print(f"\n✅ Análisis forense completado exitosamente")
        print("📁 Los resultados han sido exportados a archivos")
    else:
        print(f"\n❌ Fallo en el análisis forense")

if __name__ == "__main__":
    main()
    
