/**
 * is-a.page PR 自动化校验脚本 (v3.1.1 - 全能配套版)
 * 特性:
 *  - 兼容 JSON 注释 (// 和 /* * /)
 *  - 自动识别并校验 A / AAAA / CNAME / TXT / MX / REDIRECT
 * 校验模式 (通过环境变量 VALIDATION_MODE 设置): 
 *  - loose (宽松): 默认。仅检查是否包含基本元素，允许保留域名(仅警告)，允许缺少 owner。
 *  - normal (普通): 拦截保留域名和黑名单，强制要求填写 owner.username，校验 URL 协议。
 *  - strict (严格): 强制要求 owner.email，严格匹配 IP/IPv6/CNAME 格式。
 */

const fs = require('fs');
const path = require('path');
const { URL } = require('url');

// 读取环境变量中的模式，默认为 loose
const VALIDATION_MODE = process.env.VALIDATION_MODE || 'loose';

// --- 基础公开配置 ---
const RESERVED_DOMAINS = new Set([
  'www', 'api', 'blog', 'mail', 'smtp', 'pop', 'imap', 
  'support', 'admin', 'root', 'status', 'billing', 'cdn', 'test',
  'dev', 'staging', 'prod', 'official', 'security', 'ns1', 'ns2', 'this',
  'that', 'what', 'how', 'who', 'where', 'when', 'the', 'connect', 'login',
  'sign', 'live'
]);

const PUBLIC_BLOCKLIST = [
  'porn', 'sex', 'casino', 'gambling', 'viagra', 'hack', 'phishing', 'scam', 'spam', 'vpn', 'proxy'
];

/**
 * 🛠️ 安全的 JSON 注释剥离器
 * 能够移除 // 单行注释 和 /* 多行注释，同时保护双引号内的 URL (如 https://) 不受影响
 */
function parseJSONWithComments(jsonString) {
  const cleaned = jsonString.replace(/\\"|"(?:\\"|[^"])*"|(\/\/.*|\/\*[\s\S]*?\*\/)/g, (m, g) => g ? "" : m);
  return JSON.parse(cleaned);
}

function validateFile(filename, data) {
  const errors = [];
  const warnings = [];
  const subdomain = filename.replace('.json', '').toLowerCase();

  // === 0. 基础域名格式校验 (RFC 1123) ===
  if (subdomain.length < 4) {
    errors.push(`Subdomain "${subdomain}" is too short. Minimum length is 4 characters.`);
  }
  const labelRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
  if (!labelRegex.test(subdomain)) {
    errors.push('Invalid subdomain format. Allowed: lowercase letters, numbers, hyphens. No start/end hyphens. Length 1-63.');
  }

  // === 1. 级别 0：所有模式都必须满足的最基本元素 (向下兼容) ===
  if (!data.type) {
    errors.push('Missing "type" field. Allowed: A, AAAA, CNAME, TXT, MX, REDIRECT.');
    return { errors, warnings }; // 缺少类型直接返回，无法继续后续校验
  }

  const type = String(data.type).toUpperCase();
  const allowedTypes = ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'REDIRECT'];
  if (!allowedTypes.includes(type)) {
    errors.push(`Invalid type "${data.type}". Allowed: ${allowedTypes.join(', ')}.`);
  }

  // 容错提取：无论用户把目标填在哪个字段，都尝试抓取
  const target = data.content || data.value || data.target || data.url || data.cname || data.ip || data.ipv6 || data.txt || data.mx;
  if (!target) {
    errors.push(`Missing routing target for type ${type}. Please provide a target value (e.g., "content": "...").`);
  }

  // === 2. 级别 1：宽松模式下的警告 (Loose) ===
  if (VALIDATION_MODE === 'loose') {
    if (RESERVED_DOMAINS.has(subdomain)) {
      warnings.push('Warning: This subdomain is reserved. (Allowed in loose mode)');
    }
    if (!data.owner || !data.owner.username) {
      warnings.push('Warning: Missing "owner.username". (Allowed in loose mode)');
    }
  }

  // === 3. 级别 2：普通与严格模式 (Normal & Strict) ===
  if (VALIDATION_MODE === 'normal' || VALIDATION_MODE === 'strict') {
    if (RESERVED_DOMAINS.has(subdomain)) {
      errors.push(`The subdomain "${subdomain}" is reserved for official use.`);
    }
    if (PUBLIC_BLOCKLIST.some(kw => subdomain.includes(kw))) {
      errors.push('Subdomain contains forbidden keywords (Policy Violation).');
    }
    if (!data.owner || !data.owner.username) {
      errors.push('Missing "owner.username" field. Please provide your GitHub username.');
    }
    
    // Redirect 基本协议校验
    if (type === 'REDIRECT' && target) {
      try {
        const urlObj = new URL(target);
        if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
          errors.push('Redirect URL must start with http:// or https://');
        }
      } catch (e) {
        errors.push(`Invalid Redirect URL format: "${target}"`);
      }
    }
  }

  // === 4. 级别 3：严格模式特供 - 强校验数据格式 (Strict) ===
  if (VALIDATION_MODE === 'strict' && target) {
    if (!data.owner || !data.owner.email) {
      errors.push('Missing "owner.email" field (Required in strict mode).');
    }
    
    if (type === 'A') {
      const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
      if (!ipRegex.test(target)) {
        errors.push(`Type "A" requires a valid IPv4 address. Got: "${target}"`);
      }
    }
    
    if (type === 'AAAA') {
      // 基础 IPv6 校验 (必须包含冒号且仅包含 hex 和冒号)
      if (!/^[0-9a-fA-F:]+$/.test(target) || !target.includes(':')) {
        errors.push(`Type "AAAA" requires a valid IPv6 address. Got: "${target}"`);
      }
    }
    
    if (type === 'CNAME') {
      if (target.includes('://') || target.includes('/')) {
        errors.push(`Invalid CNAME target: "${target}". It must be a domain name, not a URL.`);
      }
    }

    if (type === 'MX') {
      if (target.includes('://') || target.includes('/')) {
        errors.push(`Invalid MX target: "${target}". It must be a mail server domain, not a URL.`);
      }
      if (data.priority === undefined) {
        warnings.push('Warning: Missing "priority" field for MX record. Will automatically default to 10 in deployment.');
      }
    }
  }

  return { errors, warnings };
}

function main() {
  console.log(`🔍 Starting PR Validation (Mode: ${VALIDATION_MODE.toUpperCase()})...\n`);

  const domainsDir = path.join(__dirname, '../domains');
  if (!fs.existsSync(domainsDir)) {
    console.error('❌ Error: "domains" directory not found.');
    process.exit(1);
  }

  const files = fs.readdirSync(domainsDir).filter(f => f.endsWith('.json'));
  let hasError = false;
  let checkedCount = 0;

  for (const file of files) {
    const filePath = path.join(domainsDir, file);
    let data;

    // A. 预处理并解析 JSON (剥离注释)
    try {
      const fileContent = fs.readFileSync(filePath, 'utf8');
      data = parseJSONWithComments(fileContent);
    } catch (err) {
      console.error(`❌ [${file}] JSON Parse Error:`);
      console.error(`   ${err.message}`);
      console.error('   Please check for missing commas or unescaped quotes.\n');
      hasError = true;
      continue;
    }

    // B. 执行分级校验逻辑
    const { errors, warnings } = validateFile(file, data);
    
    // 打印警告 (不阻断进程)
    if (warnings.length > 0) {
      console.log(`⚠️ [${file}] Warnings:`);
      warnings.forEach(warn => console.log(`   - ${warn}`));
    }

    // 打印错误 (阻断进程)
    if (errors.length > 0) {
      console.error(`❌ [${file}] Validation Failed:`);
      errors.forEach(err => console.error(`   - ${err}`));
      console.error(''); // 换行美化
      hasError = true;
    }
    
    checkedCount++;
  }

  if (hasError) {
    console.error(`🚨 Validation failed! Please fix the errors above before merging.`);
    process.exit(1); // 失败，拦截 PR
  } else {
    console.log(`\n✅ All ${checkedCount} domain files passed validation! Ready to merge.`);
    process.exit(0); // 成功，允许 PR 合并
  }
}

main();
