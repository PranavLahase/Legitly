const CONFIG = {
  API: {
    BASE_URL: 'https://generativelanguage.googleapis.com/v1beta/models',
    MODEL: 'gemini-1.5-flash-latest', // Supported model in Gemini API
    MAX_RETRIES: 3,
    RETRY_DELAY: 1000
  },
  CACHE: {
    DURATION: 3600,
    PREFIX: 'legitly_v3_'
  },
  VALIDATION: {
    MAX_TEXT_LENGTH: 50000,
    MAX_URL_LENGTH: 2000,
    SUPPORTED_LANGUAGES: [
      'English','Hindi','Marathi','Bengali','Telugu','Tamil','Gujarati','Urdu',
      'Kannada','Malayalam','Punjabi','Odia','Assamese',
      'Spanish','Chinese','French','Arabic','Portuguese','Russian',
      'Japanese','German','Korean','Italian','Vietnamese','Turkish'
    ]
  },
  CYBERCRIME: {
    INDIA_PORTAL: 'https://cybercrime.gov.in/Accept.aspx',
    HELPLINE: '1930'
  }
};

/**
 * Serve the UI (file must be named index in Apps Script project)
 */
function doGet() {
  return HtmlService.createHtmlOutputFromFile('index').setTitle('Legitly — Know the difference');
}

/**
 * Main verification entrypoint
 * requestData = { type: 'text'|'news'|'image'|'deepfake'|'video', data: string, language?: string, showDemo?: boolean }
 */
function performVerification(requestData) {
  const requestId = generateRequestId();
  const startTime = Date.now();

  try {
    const validation = validateRequest(requestData);
    if (!validation.isValid) {
      return createErrorResponse('VALIDATION_ERROR', validation.errors.join(', '), requestId);
    }

    const cacheKey = generateCacheKey(requestData);
    const cached = getCachedResult(cacheKey);
    if (cached) {
      return enhanceResponse(cached, requestId, Date.now() - startTime, true);
    }

    let result;
    if (requestData.type === 'text' || requestData.type === 'news') {
      result = analyzeTextContent(requestData, requestId);
    } else if (requestData.type === 'image') {
      result = analyzeImageContent(requestData, requestId);
    } else if (requestData.type === 'deepfake' || requestData.type === 'video') {
      result = analyzeVideoContent(requestData, requestId);
    } else {
      return createErrorResponse('INVALID_TYPE', 'Supported types: text, news, image, deepfake, video', requestId);
    }

    if (result && !result.error) {
      setCachedResult(cacheKey, result);
    }
    return enhanceResponse(result, requestId, Date.now() - startTime, false);

  } catch (err) {
    return createErrorResponse('SYSTEM_ERROR', 'Analysis failed. Please try again.', requestId);
  }
}

/**
 * Text/News analysis with enhanced cyber crime detection
 */
function analyzeTextContent(requestData, requestId) {
  const language = requestData.language || 'English';
  const content = requestData.data;

  const prompt =
    'You are Legitly, an expert content verification system. Analyze this content for legitimacy and misinformation.\n' +
    '\nANALYSIS FRAMEWORK:\n' +
    '- Credibility: Source reliability, logical consistency, fact patterns\n' +
    '- Misinformation: False claims, misleading information, manipulation\n' +
    '- Context: Current events, cultural awareness, temporal relevance\n' +
    '- Risk: Potential harm, spread likelihood, urgency\n' +
    '- Cyber Crime: Check for scams, fraud, malicious content, financial fraud, fake schemes\n' +
    '\nRESPONSE LANGUAGE: ' + language + '\n' +
    '\nReturn ONLY valid JSON with no other text:\n' +
    '{\n' +
    '  "tldr": "One of: \'Verified\', \'Likely True\', \'Mixed\', \'Likely False\', \'False\', \'Unverified\'",\n' +
    '  "legitimate": true/false/null,\n' +
    '  "score": 0-100,\n' +
    '  "confidence": 0.0-1.0,\n' +
    '  "risk_level": "Low/Medium/High/Critical",\n' +
    '  "summary": "Brief summary of content",\n' +
    '  "report": "Clear explanation in ' + language + '",\n' +
    '  "keywords": ["key","indicators","found"],\n' +
    '  "reasoning": "Why this score was assigned",\n' +
    '  "sources_needed": true/false,\n' +
    '  "cyber_crime_detected": true/false,\n' +
    '  "crime_type": "Type of cyber crime if detected or null",\n' +
    '  "report_recommended": true/false\n' +
    '}\n' +
    '\nContent to analyze: ' + content;

  const result = callGeminiAPI(prompt, requestId, 'text');
  
  // Add cyber crime portal info if crime detected
  if (result && result.cyber_crime_detected) {
    result.cyber_crime_info = {
      portal_url: CONFIG.CYBERCRIME.INDIA_PORTAL,
      helpline: CONFIG.CYBERCRIME.HELPLINE,
      message: language === 'Hindi' ? 
        'संभावित साइबर अपराध की पहचान की गई। रिपोर्ट करने के लिए साइबर अपराध पोर्टल पर जाएं।' :
        'Potential cyber crime detected. Visit the National Cyber Crime Portal to report.'
    };
  }
  
  return result;
}

/**
 * Image analysis with enhanced fraud detection
 */
function analyzeImageContent(requestData, requestId) {
  const language = requestData.language || 'English';
  const imageData = requestData.data;

  const prompt =
    'You are Legitly, analyzing this image for authenticity and misinformation.\n\n' +
    'Examine for:\n' +
    '- Digital manipulation signs\n' +
    '- Text content and accuracy\n' +
    '- Visual authenticity indicators\n' +
    '- Context and credibility\n' +
    '- Fraudulent schemes, fake certificates, scam content\n\n' +
    'RESPONSE LANGUAGE: ' + language + '\n\n' +
    'Return ONLY valid JSON:\n' +
    '{\n' +
    '  "tldr": "One of: \'Authentic\', \'Likely Real\', \'Suspicious\', \'Likely Fake\', \'Manipulated\'",\n' +
    '  "legitimate": true/false/null,\n' +
    '  "score": 0-100,\n' +
    '  "confidence": 0.0-1.0,\n' +
    '  "risk_level": "Low/Medium/High/Critical",\n' +
    '  "summary": "What this image shows",\n' +
    '  "report": "Analysis explanation in ' + language + '",\n' +
    '  "keywords": ["visual","indicators","found"],\n' +
    '  "reasoning": "Why this authenticity score",\n' +
    '  "sources_needed": true/false,\n' +
    '  "cyber_crime_detected": true/false,\n' +
    '  "crime_type": "Type of fraud if detected or null",\n' +
    '  "report_recommended": true/false,\n' +
    '  "image_analysis": {\n' +
    '    "text_detected": "Any text found or \'None\'",\n' +
    '    "text_language": "Language of text or \'N/A\'",\n' +
    '    "text_translation": "English translation or \'N/A\'",\n' +
    '    "visual_elements": ["key","objects","identified"],\n' +
    '    "manipulation_signs": ["editing","indicators","found"],\n' +
    '    "authenticity_indicators": ["genuine","signs","found"]\n' +
    '  }\n' +
    '}';

  const result = callGeminiAPI(prompt, requestId, 'image', imageData);
  
  // Add cyber crime portal info if fraud detected
  if (result && result.cyber_crime_detected) {
    result.cyber_crime_info = {
      portal_url: CONFIG.CYBERCRIME.INDIA_PORTAL,
      helpline: CONFIG.CYBERCRIME.HELPLINE,
      message: language === 'Hindi' ? 
        'संभावित धोखाधड़ी या फर्जी सामग्री की पहचान की गई। साइबर अपराध पोर्टल पर रिपोर्ट करें।' :
        'Potential fraud or fake content detected. Report to National Cyber Crime Portal.'
    };
  }
  
  return result;
}

/**
 * Video/Deepfake analysis (same as your original)
 */
function analyzeVideoContent(requestData, requestId) {
  const videoUrl = requestData.data;
  const language = requestData.language || 'English';

  if (requestData.showDemo) {
    return {
      tldr: "In Development",
      legitimate: null,
      score: 0,
      confidence: 1.0,
      risk_level: "Unknown",
      summary: "Advanced deepfake detection is being developed",
      report: language === 'Hindi' ? 
        'यह सुविधा विकसित की जा रही है। यह वीडियो में डीपफेक की पहचान करेगी।' :
        'This feature is under development. It will detect deepfakes and AI-generated videos.',
      keywords: ["deepfake detection","under development","coming soon"],
      reasoning: "Feature uses advanced video processing capabilities",
      sources_needed: false,
      video_analysis: {
        platform: "Multiple platforms supported",
        deepfake_probability: "Will provide accurate detection",
        recommendation: "Advanced AI-powered video verification"
      }
    };
  }

  const urlAnalysis = analyzeVideoUrl(videoUrl, language);
  return {
    tldr: urlAnalysis.legitimate === true ? "Likely Authentic" :
          urlAnalysis.legitimate === false ? "Suspicious" : "Requires Verification",
    legitimate: urlAnalysis.legitimate,
    score: urlAnalysis.score,
    confidence: 0.7,
    risk_level: urlAnalysis.risk_level,
    summary: 'Video analysis for ' + extractPlatform(videoUrl) + ' content',
    report: urlAnalysis.report,
    keywords: urlAnalysis.keywords,
    reasoning: "Preliminary assessment based on URL analysis",
    sources_needed: true,
    video_analysis: {
      platform: extractPlatform(videoUrl),
      url_assessment: urlAnalysis.url_suspicious ? 'Suspicious' : 'Normal',
      deepfake_probability: urlAnalysis.score < 40 ? 'High' :
                           urlAnalysis.score < 70 ? 'Medium' : 'Low',
      recommendation: "Manual verification recommended for complete analysis"
    }
  };
}

// [Rest of your original functions remain the same - analyzeVideoUrl, extractPlatform, etc.]
function analyzeVideoUrl(url, language) {
  const platform = extractPlatform(url);
  let score = 50;
  let legitimate = null;
  let keywords = ['video analysis'];
  let report = '';
  let risk_level = 'Medium';
  let url_suspicious = false;

  const legitPlatforms = ['instagram.com','youtube.com','youtu.be','facebook.com','tiktok.com'];
  const isLegitPlatform = legitPlatforms.some(function(p){ return url.toLowerCase().indexOf(p) !== -1; });
  if (isLegitPlatform) { score += 20; keywords.push('known platform'); }
  else { score -= 20; url_suspicious = true; keywords.push('unknown platform'); }

  if (url.indexOf('reel') !== -1 || url.indexOf('/p/') !== -1 || url.indexOf('watch?v=') !== -1) {
    score += 10; keywords.push('standard format');
  }

  const suspiciousPatterns = ['bit.ly','t.co','tinyurl','shortened','fake','generated','deepfake','ai-made'];
  const hasSuspiciousPattern = suspiciousPatterns.some(function(pattern){ return url.toLowerCase().indexOf(pattern) !== -1; });
  if (hasSuspiciousPattern) { score -= 30; url_suspicious = true; keywords.push('suspicious link'); risk_level = 'High'; }

  if (score >= 70) {
    legitimate = true; risk_level = 'Low';
    report = language === 'Hindi' ? 'यह वीडियो URL सामान्य दिखता है, लेकिन सामग्री भी जांचें।' : 'This video URL looks normal, but also check the content.';
  } else if (score <= 30) {
    legitimate = false; risk_level = 'High';
    report = language === 'Hindi' ? 'यह URL संदिग्ध है। स्रोत की जांच करें।' : 'This URL looks suspicious. Verify the source.';
  } else {
    report = language === 'Hindi' ? 'प्रामाणिकता स्पष्ट नहीं है। मैन्युअल जांच करें।' : 'Authenticity unclear. Manual verification recommended.';
  }

  return {
    legitimate: legitimate,
    score: Math.max(0, Math.min(100, score)),
    risk_level: risk_level,
    report: report,
    keywords: keywords,
    url_suspicious: url_suspicious
  };
}

function extractPlatform(url) {
  const u = url.toLowerCase();
  if (u.indexOf('instagram') !== -1) return 'Instagram';
  if (u.indexOf('youtube') !== -1 || u.indexOf('youtu.be') !== -1) return 'YouTube';
  if (u.indexOf('facebook') !== -1) return 'Facebook';
  if (u.indexOf('tiktok') !== -1) return 'TikTok';
  if (u.indexOf('twitter') !== -1 || u.indexOf('x.com') !== -1) return 'X (Twitter)';
  return 'Unknown Platform';
}

/**
 * Gemini API caller with regex-free JSON extraction
 */
function callGeminiAPI(prompt, requestId, type, mediaData) {
  const apiKey = getApiKey();
  if (!apiKey) return createErrorResponse('API_KEY_MISSING', 'Please configure your Gemini API key', requestId);

  const apiUrl = CONFIG.API.BASE_URL + '/' + CONFIG.API.MODEL + ':generateContent?key=' + apiKey;

  var payload = { generationConfig: { temperature: 0.1, topK: 40, topP: 0.8, maxOutputTokens: 2048, candidateCount: 1 } };
  if (type === 'text') {
    payload.contents = [{ parts: [{ text: prompt }] }];
  } else if (type === 'image' && mediaData) {
    payload.contents = [{ parts: [{ text: prompt }, { inline_data: { mime_type: "image/jpeg", data: mediaData } }] }];
  }

  for (var attempt = 1; attempt <= CONFIG.API.MAX_RETRIES; attempt++) {
    try {
      var options = { method: 'POST', contentType: 'application/json', payload: JSON.stringify(payload), muteHttpExceptions: true, followRedirects: true };
      var response = UrlFetchApp.fetch(apiUrl, options);
      var code = response.getResponseCode();

      if (code === 200) {
        var responseData = JSON.parse(response.getContentText());
        if (!responseData.candidates || !responseData.candidates[0]) {
          return createErrorResponse('INVALID_API_RESPONSE', 'Empty AI response', requestId);
        }
        var aiText = responseData.candidates[0].content.parts[0].text || '';
        var jsonString = extractJSONObjectFromText(aiText);
        if (!jsonString) return createErrorResponse('PARSE_ERROR', 'Could not locate JSON in AI output', requestId);
        var parsed = JSON.parse(jsonString);
        return sanitizeAnalysisResult(parsed);
      } else {
        if (code >= 400 && code < 500 && code !== 429) return createErrorResponse('API_CLIENT_ERROR', 'API request error: ' + code, requestId);
        if (attempt < CONFIG.API.MAX_RETRIES) { Utilities.sleep(CONFIG.API.RETRY_DELAY * attempt); continue; }
        return createErrorResponse('API_SERVER_ERROR', 'Gemini service temporarily unavailable', requestId);
      }
    } catch (err) {
      if (attempt === CONFIG.API.MAX_RETRIES) return createErrorResponse('API_CONNECTION_ERROR', 'Failed to connect to Gemini API', requestId);
      Utilities.sleep(CONFIG.API.RETRY_DELAY * attempt);
    }
  }
}

/**
 * Extract first balanced JSON object from text (no regex)
 */
function extractJSONObjectFromText(text) {
  if (typeof text !== 'string' || !text) return null;

  var t = text.trim();
  if (t[0] === '{' && t.lastIndexOf('}') > 0) { try { JSON.parse(t); return t; } catch (e) {} }

  var s = text;
  for (var i = 0; i < 4; i++) { s = s.split('``````').join(''); }

  var inString = false, escape = false, depth = 0, start = -1;
  for (var j = 0; j < s.length; j++) {
    var ch = s[j];
    if (inString) { if (escape) { escape = false; } else if (ch === '\\') { escape = true; } else if (ch === '"') { inString = false; } continue; }
    if (ch === '"') { inString = true; continue; }
    if (ch === '{') { if (depth === 0) start = j; depth++; }
    else if (ch === '}') {
      depth--;
      if (depth === 0 && start !== -1) {
        var cand = s.slice(start, j + 1);
        try { JSON.parse(cand); return cand; } catch (e) {}
      }
    }
  }
  return null;
}

/**
 * Enhanced sanitize AI response with cyber crime fields
 */
function sanitizeAnalysisResult(result) {
  return {
    tldr: String(result.tldr || 'Unknown').substring(0, 50),
    legitimate: typeof result.legitimate === 'boolean' ? result.legitimate : null,
    score: Math.max(0, Math.min(100, parseInt(result.score, 10) || 50)),
    confidence: Math.max(0, Math.min(1, parseFloat(result.confidence) || 0.5)),
    risk_level: ['Low','Medium','High','Critical'].indexOf(result.risk_level) !== -1 ? result.risk_level : 'Medium',
    summary: String(result.summary || 'Content analyzed').substring(0, 500),
    report: String(result.report || 'Analysis completed').substring(0, 1000),
    keywords: Array.isArray(result.keywords) ? result.keywords.slice(0, 6).map(function(k){ return String(k).substring(0,50); }) : [],
    reasoning: String(result.reasoning || '').substring(0, 500),
    sources_needed: Boolean(result.sources_needed),
    cyber_crime_detected: Boolean(result.cyber_crime_detected),
    crime_type: result.crime_type ? String(result.crime_type).substring(0, 100) : null,
    report_recommended: Boolean(result.report_recommended),
    cyber_crime_info: result.cyber_crime_info || undefined,
    image_analysis: result.image_analysis ? {
      text_detected: String(result.image_analysis.text_detected || 'None'),
      text_language: String(result.image_analysis.text_language || 'N/A'),
      text_translation: String(result.image_analysis.text_translation || 'N/A'),
      visual_elements: Array.isArray(result.image_analysis.visual_elements) ? result.image_analysis.visual_elements.slice(0,5) : [],
      manipulation_signs: Array.isArray(result.image_analysis.manipulation_signs) ? result.image_analysis.manipulation_signs.slice(0,5) : [],
      authenticity_indicators: Array.isArray(result.image_analysis.authenticity_indicators) ? result.image_analysis.authenticity_indicators.slice(0,5) : []
    } : undefined,
    video_analysis: result.video_analysis ? {
      platform: String(result.video_analysis.platform || 'Unknown'),
      deepfake_probability: String(result.video_analysis.deepfake_probability || 'Unknown'),
      recommendation: String(result.video_analysis.recommendation || 'Manual review recommended')
    } : undefined
  };
}

// [Rest of your utility functions remain exactly the same]
function validateRequest(requestData) {
  var errors = [];
  if (!requestData || typeof requestData !== 'object') { errors.push('Invalid request format'); return { isValid:false, errors:errors }; }

  var allowed = ['text','news','image','deepfake','video'];
  if (!requestData.type || allowed.indexOf(requestData.type) === -1) { errors.push('Type must be: ' + allowed.join(', ')); }

  if (!requestData.data || typeof requestData.data !== 'string') { errors.push('Data field is required and must be text'); }

  if ((requestData.type === 'text' || requestData.type === 'news') && requestData.data) {
    if (requestData.data.length < 10) errors.push('Text must be at least 10 characters long');
    if (requestData.data.length > CONFIG.VALIDATION.MAX_TEXT_LENGTH) errors.push('Text too long (max ' + CONFIG.VALIDATION.MAX_TEXT_LENGTH + ')');
  }

  if ((requestData.type === 'deepfake' || requestData.type === 'video') && requestData.data) {
    if (requestData.data.indexOf('http') !== 0) errors.push('Invalid URL format - must start with http');
    if (requestData.data.length > CONFIG.VALIDATION.MAX_URL_LENGTH) errors.push('URL too long');
  }

  if (requestData.language && CONFIG.VALIDATION.SUPPORTED_LANGUAGES.indexOf(requestData.language) === -1) {
    errors.push('Unsupported language. Available: ' + CONFIG.VALIDATION.SUPPORTED_LANGUAGES.join(', '));
  }

  return { isValid: errors.length === 0, errors: errors };
}

function getApiKey() {
  try { return PropertiesService.getScriptProperties().getProperty('GEMINI_API_KEY') || PropertiesService.getUserProperties().getProperty('GEMINI_API_KEY'); }
  catch (e) { return null; }
}
function setApiKey(apiKey) { if (!apiKey || apiKey.length < 30) throw new Error('Invalid API key'); PropertiesService.getScriptProperties().setProperty('GEMINI_API_KEY', apiKey); }

function generateCacheKey(requestData) {
  var keyData = JSON.stringify({ type: requestData.type, data: requestData.data, language: requestData.language || 'English' });
  return CONFIG.CACHE.PREFIX + Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, keyData);
}
function getCachedResult(cacheKey) { try { var c=CacheService.getScriptCache(); var v=c.get(cacheKey); return v?JSON.parse(v):null; } catch(e){ return null; } }
function setCachedResult(cacheKey, result) { try { CacheService.getScriptCache().put(cacheKey, JSON.stringify(result), CONFIG.CACHE.DURATION); } catch(e){} }

function generateRequestId() { return 'req_' + Date.now() + '_' + Math.random().toString(36).substr(2,5); }
function createErrorResponse(errorType, message, requestId) { return { error:true, errorType:errorType, message:message, requestId:requestId, timestamp:new Date().toISOString() }; }
function enhanceResponse(res, requestId, ms, fromCache){ if(res.error) return res; res.metadata={requestId:requestId,processingTime:ms,fromCache:fromCache,version:'3.3'}; return res; }
function getSystemStatus(){ var ok=!!getApiKey(); return { status: ok?'Ready - Gemini 1.5 Flash':'Setup Required', model:CONFIG.API.MODEL, features:['Text','Image','Video URL','25+ Languages','Cyber Crime Detection'], version:'3.3' }; }
