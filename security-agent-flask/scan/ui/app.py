"""
Flask UI for testcloud - AWS Posture Scanner
"""
import os
import json
import threading
import time
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'testcloud-dev-key')

# Paths
BASE_DIR = Path(__file__).parent.parent
SCAN_DIR = BASE_DIR / 'scans'
SCAN_DIR.mkdir(exist_ok=True)

# Global scan status
scan_status = {
    'running': False,
    'progress': 0,
    'message': '',
    'result_file': None,
    'error': None
}

def run_scan_async(args, output_file):
    """Run scan in background thread using the module directly"""
    global scan_status
    scan_status['running'] = True
    scan_status['progress'] = 0
    scan_status['message'] = 'Iniciando scan...'
    scan_status['result_file'] = None
    scan_status['error'] = None
    
    try:
        # Import the module components directly
        import sys
        sys.path.insert(0, str(BASE_DIR))
        
        from testcloud.context import SessionFactory
        from testcloud.engine import Scanner
        from testcloud.models import Severity
        from testcloud.registry import select
        from testcloud.report import write_json
        
        # Parse args into proper parameters
        profile = None
        role_arn = None
        external_id = None
        regions = None
        pillars = None
        services = None
        include = None
        exclude = None
        min_severity = 'info'
        workers = 8
        
        i = 0
        while i < len(args):
            if args[i] == '--profile':
                profile = args[i + 1]
                i += 2
            elif args[i] == '--role-arn':
                role_arn = args[i + 1]
                i += 2
            elif args[i] == '--external-id':
                external_id = args[i + 1]
                i += 2
            elif args[i] == '--regions':
                regions = []
                i += 1
                while i < len(args) and not args[i].startswith('--'):
                    regions.append(args[i])
                    i += 1
            elif args[i] == '--pillars':
                pillars = []
                i += 1
                while i < len(args) and not args[i].startswith('--'):
                    pillars.append(args[i])
                    i += 1
            elif args[i] == '--services':
                services = []
                i += 1
                while i < len(args) and not args[i].startswith('--'):
                    services.append(args[i])
                    i += 1
            elif args[i] == '--check':
                include = []
                i += 1
                while i < len(args) and not args[i].startswith('--'):
                    include.append(args[i])
                    i += 1
            elif args[i] == '--skip':
                exclude = []
                i += 1
                while i < len(args) and not args[i].startswith('--'):
                    exclude.append(args[i])
                    i += 1
            elif args[i] == '--min-severity':
                min_severity = args[i + 1]
                i += 2
            elif args[i] == '--workers':
                workers = int(args[i + 1])
                i += 2
            else:
                i += 1
        
        # Update progress
        scan_status['progress'] = 5
        scan_status['message'] = 'Configurando scan...'
        
        # Select checks
        checks = select(
            pillars=pillars, services=services, include=include, exclude=exclude
        )
        if not checks:
            raise ValueError("Nenhum check corresponde aos filtros informados.")
        
        scan_status['progress'] = 10
        scan_status['message'] = 'Criando factory de sessão...'
        
        # Create factory
        factory = SessionFactory(
            profile=profile, role_arn=role_arn, external_id=external_id
        )
        
        # Progress callback
        def progress_cb(check_id: str, region: str, done: int, total: int) -> None:
            pct = 10 + (done * 85 // max(total, 1))
            scan_status['progress'] = min(pct, 95)
            scan_status['message'] = f'[{pct:>3}%] {done}/{total}  {region:<16} {check_id:<34}'
        
        # Create scanner
        scanner = Scanner(
            factory=factory,
            checks_to_run=checks,
            regions=regions,
            max_workers=workers,
            progress=progress_cb,
        )
        
        scan_status['progress'] = 15
        scan_status['message'] = 'Executando scan...'
        
        # Run scan
        result = scanner.run()
        
        scan_status['progress'] = 95
        scan_status['message'] = 'Processando resultados...'
        
        # Filter by min severity
        floor = Severity(min_severity)
        result.findings = [f for f in result.findings if f.severity.weight >= floor.weight]
        
        # Write JSON output
        write_json(result, output_file)
        
        scan_status['progress'] = 100
        scan_status['message'] = 'Scan concluído com sucesso!'
        scan_status['result_file'] = output_file.name
        
    except Exception as e:
        scan_status['error'] = str(e)
        scan_status['message'] = 'Erro ao executar scan'
    finally:
        scan_status['running'] = False

@app.route('/')
def index():
    """Main dashboard"""
    # List previous scans
    scans = []
    for f in sorted(SCAN_DIR.glob('scan_*.json'), reverse=True):
        try:
            with open(f) as fp:
                data = json.load(fp)
            scans.append({
                'file': f.name,
                'timestamp': data.get('started_at', ''),
                'account': data.get('account_id', ''),
                'regions': len(data.get('regions', [])),
                'findings': len(data.get('findings', [])),
                'critical': sum(1 for f in data.get('findings', []) if f.get('severity', '').lower() == 'critical'),
                'high': sum(1 for f in data.get('findings', []) if f.get('severity', '').lower() == 'high'),
                'medium': sum(1 for f in data.get('findings', []) if f.get('severity', '').lower() == 'medium'),
                'low': sum(1 for f in data.get('findings', []) if f.get('severity', '').lower() == 'low'),
            })
        except:
            pass
    
    return render_template('index.html', scans=scans)

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Scan configuration and execution"""
    if request.method == 'POST':
        # Build scan arguments
        args = []
        
        profile = request.form.get('profile')
        if profile:
            args.extend(['--profile', profile])
        
        role_arn = request.form.get('role_arn')
        if role_arn:
            args.extend(['--role-arn', role_arn])
        
        external_id = request.form.get('external_id')
        if external_id:
            args.extend(['--external-id', external_id])
        
        regions = request.form.get('regions')
        if regions:
            args.extend(['--regions'] + regions.split())
        
        pillars = request.form.get('pillars')
        if pillars:
            args.extend(['--pillars'] + pillars.split())
        
        services = request.form.get('services')
        if services:
            args.extend(['--services'] + services.split())
        
        min_severity = request.form.get('min_severity', 'info')
        args.extend(['--min-severity', min_severity])
        
        workers = request.form.get('workers', '8')
        args.extend(['--workers', workers])
        
        # Generate output filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = SCAN_DIR / f'scan_{timestamp}.json'
        
        # Start async scan
        thread = threading.Thread(target=run_scan_async, args=(args, output_file))
        thread.start()
        
        flash('Scan iniciado! Acompanhe o progresso abaixo.', 'success')
        return redirect(url_for('scan_status_page', filename=output_file.name))
    
    return render_template('scan.html')

@app.route('/scan/status/<filename>')
def scan_status_page(filename):
    """Scan progress page"""
    # Get initial status for immediate UI rendering
    initial_status = scan_status.copy() if scan_status else None
    return render_template('scan_status.html', filename=filename, initial_status=initial_status)

@app.route('/api/scan/status')
def api_scan_status():
    """API endpoint for scan status"""
    return jsonify(scan_status)

@app.route('/results/<filename>')
def results(filename):
    """View scan results"""
    filepath = SCAN_DIR / filename
    if not filepath.exists():
        flash('Arquivo de resultado não encontrado', 'error')
        return redirect(url_for('index'))
    
    with open(filepath) as f:
        data = json.load(f)
    
    # Filter findings
    severity_filter = request.args.get('severity', 'all')
    pillar_filter = request.args.get('pillar', 'all')
    search = request.args.get('search', '').lower()
    
    findings = data.get('findings', [])
    
    if severity_filter != 'all':
        findings = [f for f in findings if f.get('severity', '').lower() == severity_filter.lower()]
    
    if pillar_filter != 'all':
        findings = [f for f in findings if f.get('pillar') == pillar_filter]
    
    if search:
        findings = [f for f in findings if search in f.get('title', '').lower() 
                   or search in f.get('description', '').lower()
                   or search in f.get('resource_id', '').lower()]
    
    # Stats
    stats = {
        'total': len(data.get('findings', [])),
        'filtered': len(findings),
        'critical': sum(1 for f in data.get('findings', []) if f.get('severity', '').lower() == 'critical'),
        'high': sum(1 for f in data.get('findings', []) if f.get('severity', '').lower() == 'high'),
        'medium': sum(1 for f in data.get('findings', []) if f.get('severity', '').lower() == 'medium'),
        'low': sum(1 for f in data.get('findings', []) if f.get('severity', '').lower() == 'low'),
    }
    
    return render_template('results.html', 
                         data=data, 
                         findings=findings, 
                         stats=stats,
                         filename=filename,
                         severity_filter=severity_filter,
                         pillar_filter=pillar_filter,
                         search=search)


@app.route('/results/<filename>/<int:index>')
def finding_detail(filename, index):
    """View a single finding detail page"""
    filepath = SCAN_DIR / filename
    if not filepath.exists():
        flash('Arquivo de resultado não encontrado', 'error')
        return redirect(url_for('index'))
    
    with open(filepath) as f:
        data = json.load(f)
    
    findings = data.get('findings', [])
    if index < 0 or index >= len(findings):
        flash('Achado não encontrado', 'error')
        return redirect(url_for('results', filename=filename))
    
    finding = findings[index]
    
    # Severity label/color helpers
    severity_meta = {
        'critical': {'label': 'CRÍTICO', 'color': 'danger'},
        'high': {'label': 'ALTO', 'color': 'warning'},
        'medium': {'label': 'MÉDIO', 'color': 'warning'},
        'low': {'label': 'BAIXO', 'color': 'info'},
        'info': {'label': 'INFO', 'color': 'secondary'},
    }
    sev = finding.get('severity', '').lower()
    meta = severity_meta.get(sev, {'label': sev.upper(), 'color': 'secondary'})
    
    pillar_meta = {
        'security': {'label': 'Segurança', 'color': 'danger'},
        'reliability': {'label': 'Confiabilidade', 'color': 'warning'},
        'cost_optimization': {'label': 'Otimização de Custo', 'color': 'success'},
    }
    pil = finding.get('pillar', '')
    pmeta = pillar_meta.get(pil, {'label': pil.replace('_', ' ').title(), 'color': 'secondary'})
    
    return render_template('finding_detail.html',
                         data=data,
                         finding=finding,
                         index=index,
                         filename=filename,
                         severity_label=meta['label'],
                         severity_color=meta['color'],
                         pillar_label=pmeta['label'],
                         pillar_color=pmeta['color'])

@app.route('/download/<filename>')
def download(filename):
    """Download scan result as JSON"""
    filepath = SCAN_DIR / filename
    if not filepath.exists():
        flash('Arquivo não encontrado', 'error')
        return redirect(url_for('index'))
    return send_file(filepath, as_attachment=True)

@app.route('/delete/<filename>', methods=['POST'])
def delete_scan(filename):
    """Delete a scan result"""
    filepath = SCAN_DIR / filename
    if filepath.exists():
        filepath.unlink()
        flash('Scan removido', 'success')
    else:
        flash('Arquivo não encontrado', 'error')
    return redirect(url_for('index'))

@app.route('/checks')
def checks_page():
    """Catálogo de checks (página dedicada)"""
    return render_template('checks.html')

@app.route('/api/checks')
def api_checks():
    """List available checks"""
    try:
        import sys
        sys.path.insert(0, str(BASE_DIR))
        # Import checks modules to populate registry
        import testcloud.checks  # noqa: F401 - popula o registry
        from testcloud.registry import all_checks
        
        checks = []
        for c in sorted(all_checks(), key=lambda c: (c.pillar.value, c.id)):
            checks.append({
                'id': c.id,
                'pillar': c.pillar.value,
                'service': c.service,
                'scope': c.scope,
                'title': c.title,
                'well_architected': c.well_architected,
                'permissions': list(c.permissions),
            })
        return jsonify(checks)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/checks/<check_id>/resources')
def api_check_resources(check_id):
    """Recursos analisados por um check no scan mais recente"""
    try:
        # Último scan disponível
        scans = sorted(SCAN_DIR.glob('scan_*.json'), reverse=True)
        if not scans:
            return jsonify({'error': 'Nenhum scan realizado ainda'}), 404

        with open(scans[0]) as f:
            data = json.load(f)

        # Checks que realmente rodaram no scan (novos scans gravam checks_run)
        checks_run = data.get('checks_run', [])
        if checks_run:
            executed = check_id in checks_run
        else:
            # Scan antigo (schema sem checks_run): não dá para saber com certeza.
            # Se o check tem findings, ele rodou; senão, desconhecido.
            executed = True if any(f.get('check_id') == check_id for f in data.get('findings', [])) else None

        findings = [f for f in data.get('findings', []) if f.get('check_id') == check_id]
        resources = []
        for f in findings:
            resources.append({
                'resource_id': f.get('resource_id', ''),
                'resource_arn': f.get('resource_arn', ''),
                'region': f.get('region', ''),
                'severity': f.get('severity', ''),
                'title': f.get('title', ''),
            })

        return jsonify({
            'check_id': check_id,
            'scan_file': scans[0].name,
            'executed': executed,
            'total_findings': len(findings),
            'resources': resources,
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)