# heisenberg/sbom_parser.py

import json
import csv
import os
import defusedxml.ElementTree as ET


def normalize_ecosystem(ecosystem):
    ecosystem = ecosystem.lower()
    if ecosystem == "golang":
        return "go"
    if ecosystem == "rust":
        return "cargo"
    return ecosystem


def clean_package_name(package_name):
    last_nm_idx = package_name.rfind("node_modules/")
    if last_nm_idx != -1:
        package_name = package_name[last_nm_idx + len("node_modules/"):]
    return package_name


def detect_format(file_path):
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()
    
    if ext == '.csv':
        return 'csv'
    
    if ext in ['.json', '.cdx']:
        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                if 'bomFormat' in data and data['bomFormat'] == 'CycloneDX':
                    return 'cyclonedx_json'
                elif 'spdxVersion' in data:
                    return 'spdx_json'
            except json.JSONDecodeError:
                pass
    
    if ext == '.xml':
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            if 'cyclonedx' in root.tag.lower():
                return 'cyclonedx_xml'
            if 'spdx' in root.tag.lower():
                return 'spdx_xml'
        except ET.ParseError:
            pass
    
    raise ValueError(f"Unable to detect SBOM format for {file_path}")
    
def parse_cyclonedx_json(file_path):
    packages = []
    
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    components = data.get('components', [])
    
    for comp in components:
        name = comp.get('name', '')
        version = comp.get('version', '')
        purl = comp.get('purl', '')
        
        ecosystem = 'unknown'
        if purl:
            try:
                ecosystem = purl.split(':')[1].split('/')[0]
            except (IndexError, AttributeError):
                pass
        
        license_info = "N/A"
        licenses = comp.get('licenses', [])
        if licenses and isinstance(licenses, list) and len(licenses) > 0:
            license_data = licenses[0]
            if isinstance(license_data, dict):
                license_info = license_data.get('license', {}).get('id') or \
                             license_data.get('license', {}).get('name') or \
                             license_data.get('expression', 'N/A')
        
        if name and version:
            packages.append({
                'name': clean_package_name(name),
                'version': version,
                'ecosystem': normalize_ecosystem(ecosystem),
                'license': license_info
            })
    
    return packages
    
def parse_cyclonedx_xml(file_path):
    packages = []
    
    tree = ET.parse(file_path)
    root = tree.getroot()
    
    ns = {'': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}
    
    components_elem = root.find('.//components', ns) if ns else root.find('.//components')
    if components_elem is None:
        return packages
    
    for comp in components_elem.findall('component', ns) if ns else components_elem.findall('component'):
        name_elem = comp.find('name', ns) if ns else comp.find('name')
        version_elem = comp.find('version', ns) if ns else comp.find('version')
        purl_elem = comp.find('purl', ns) if ns else comp.find('purl')
        
        name = name_elem.text if name_elem is not None else ''
        version = version_elem.text if version_elem is not None else ''
        purl = purl_elem.text if purl_elem is not None else ''
        
        ecosystem = 'unknown'
        if purl:
            try:
                ecosystem = purl.split(':')[1].split('/')[0]
            except (IndexError, AttributeError):
                pass
        
        license_info = "N/A"
        licenses_elem = comp.find('licenses', ns) if ns else comp.find('licenses')
        if licenses_elem is not None:
            license_elem = licenses_elem.find('.//license/id', ns) if ns else licenses_elem.find('.//license/id')
            if license_elem is not None:
                license_info = license_elem.text
            else:
                license_elem = licenses_elem.find('.//license/name', ns) if ns else licenses_elem.find('.//license/name')
                if license_elem is not None:
                    license_info = license_elem.text
        
        if name and version:
            packages.append({
                'name': clean_package_name(name),
                'version': version,
                'ecosystem': normalize_ecosystem(ecosystem),
                'license': license_info
            })
    
    return packages
    
def parse_spdx_json(file_path):
    packages = []
    
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    spdx_packages = data.get('packages', [])
    
    for pkg in spdx_packages:
        name = pkg.get('name', '')
        version = pkg.get('versionInfo', '')
        
        ecosystem = 'unknown'
        external_refs = pkg.get('externalRefs', [])
        for ref in external_refs:
            if ref.get('referenceType') == 'purl':
                locator = ref.get('referenceLocator', '')
                if locator.startswith('pkg:'):
                    try:
                        ecosystem = locator.split(':')[1].split('/')[0]
                    except (IndexError, AttributeError):
                        pass
                break
        
        license_info = pkg.get('licenseConcluded', 'N/A')
        if license_info == 'NOASSERTION' or not license_info:
            license_info = pkg.get('licenseDeclared', 'N/A')
        
        if name and version:
            packages.append({
                'name': clean_package_name(name),
                'version': version,
                'ecosystem': normalize_ecosystem(ecosystem),
                'license': license_info
            })
    
    return packages
    
def parse_spdx_xml(file_path):
    packages = []
    
    tree = ET.parse(file_path)
    root = tree.getroot()
    
    ns = {'': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}
    
    for pkg_elem in root.findall('.//package', ns) if ns else root.findall('.//package'):
        name_elem = pkg_elem.find('name', ns) if ns else pkg_elem.find('name')
        version_elem = pkg_elem.find('versionInfo', ns) if ns else pkg_elem.find('versionInfo')
        
        name = name_elem.text if name_elem is not None else ''
        version = version_elem.text if version_elem is not None else ''
        
        ecosystem = 'unknown'
        for ref_elem in pkg_elem.findall('.//externalRef', ns) if ns else pkg_elem.findall('.//externalRef'):
            ref_type_elem = ref_elem.find('referenceType', ns) if ns else ref_elem.find('referenceType')
            if ref_type_elem is not None and ref_type_elem.text == 'purl':
                locator_elem = ref_elem.find('referenceLocator', ns) if ns else ref_elem.find('referenceLocator')
                if locator_elem is not None and locator_elem.text.startswith('pkg:'):
                    try:
                        ecosystem = locator_elem.text.split(':')[1].split('/')[0]
                    except (IndexError, AttributeError):
                        pass
                    break
        
        license_info = "N/A"
        license_concluded_elem = pkg_elem.find('licenseConcluded', ns) if ns else pkg_elem.find('licenseConcluded')
        if license_concluded_elem is not None and license_concluded_elem.text != 'NOASSERTION':
            license_info = license_concluded_elem.text
        else:
            license_declared_elem = pkg_elem.find('licenseDeclared', ns) if ns else pkg_elem.find('licenseDeclared')
            if license_declared_elem is not None:
                license_info = license_declared_elem.text
        
        if name and version:
            packages.append({
                'name': clean_package_name(name),
                'version': version,
                'ecosystem': normalize_ecosystem(ecosystem),
                'license': license_info
            })
    
    return packages
    
def parse_csv(file_path):
    packages = []
    
    with open(file_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row.get('package', '').strip()
            version = row.get('version', '').strip()
            ecosystem = row.get('language', '').strip()
            license_info = row.get('license', 'N/A').strip()
            
            if name and version and ecosystem:
                packages.append({
                    'name': clean_package_name(name),
                    'version': version,
                    'ecosystem': normalize_ecosystem(ecosystem),
                    'license': license_info
                })
    
    return packages


def parse_sbom(file_path):
    fmt = detect_format(file_path)
    
    if fmt == 'cyclonedx_json':
        return parse_cyclonedx_json(file_path)
    elif fmt == 'cyclonedx_xml':
        return parse_cyclonedx_xml(file_path)
    elif fmt == 'spdx_json':
        return parse_spdx_json(file_path)
    elif fmt == 'spdx_xml':
        return parse_spdx_xml(file_path)
    elif fmt == 'csv':
        return parse_csv(file_path)
    else:
        raise ValueError(f"Unsupported SBOM format: {fmt}")