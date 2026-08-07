/**
 * Генерация QR-кода для подключения к Wi‑Fi (без внешних библиотек).
 * Сегментная оптимизация (numeric/alphanumeric) не применяется — только byte mode:
 * QR чуть крупнее для цифровых паролей, но читается всеми сканерами.
 * Пароль не логируется и не сохраняется — только передаётся в строку QR при явном вызове.
 */

/** @typedef {'WPA2'|'WPA3'|'WPA2/WPA3'|'WPA'} WifiQrSecurityMode */

/** @typedef {{ security: WifiQrSecurityMode|string, ssid: string, password: string, hidden?: boolean }} WifiQrPayload */

/** @typedef {{ version: number, mask: number, modules: boolean[][] }} WifiQrMatrixResult */

const ESCAPE_RE = /[\\;,:"]/g;

/** Предвычисленные 15-битные format info для EC=M и масок 0–7 (ISO/IEC 18004). */
const FORMAT_INFO_BITS_M = Object.freeze([
  0x5412, 0x5125, 0x5e7c, 0x5b4b, 0x45f9, 0x40ce, 0x4f97, 0x4aa0,
]);

/** Data codewords per version at EC level M. */
const DATA_CODEWORDS_M = Object.freeze([
  0,
  16, 28, 44, 64, 86, 108, 124, 154, 182, 216, 254, 290, 334, 365, 415, 453, 507, 563, 627, 669,
]);

/** EC codewords per block group at EC level M: [ [numBlocks, dataCw, ecCw], ... ]. */
const BLOCK_SPECS_M = Object.freeze([
  null,
  [[1, 16, 10]],
  [[1, 28, 16]],
  [[1, 44, 26]],
  [[2, 32, 18]],
  [[2, 43, 24]],
  [[4, 27, 16]],
  [[4, 31, 18]],
  [[2, 38, 22], [2, 39, 22]],
  [[3, 36, 22], [2, 37, 22]],
  [[4, 43, 26], [1, 44, 26]],
  [[1, 50, 30], [4, 51, 30]],
  [[6, 36, 22], [2, 37, 22]],
  [[8, 37, 22], [1, 38, 22]],
  [[4, 40, 24], [5, 41, 24]],
  [[5, 41, 24], [5, 42, 24]],
  [[7, 45, 28], [3, 46, 28]],
  [[10, 46, 28], [1, 47, 28]],
  [[9, 43, 26], [4, 44, 26]],
  [[3, 44, 26], [11, 45, 26]],
  [[3, 41, 26], [13, 42, 26]],
]);

/** Alignment pattern centers by version. */
const ALIGNMENT_CENTERS = Object.freeze([
  [],
  [],
  [6, 18],
  [6, 22],
  [6, 26],
  [6, 30],
  [6, 34],
  [6, 22, 38],
  [6, 24, 42],
  [6, 26, 46],
  [6, 28, 50],
  [6, 30, 54],
  [6, 32, 58],
  [6, 34, 62],
  [6, 26, 46, 66],
  [6, 26, 48, 70],
  [6, 26, 50, 74],
  [6, 30, 54, 78],
  [6, 30, 56, 82],
  [6, 30, 58, 86],
  [6, 34, 62, 90],
]);

/** Version info BCH (18 bits) for versions 7–40. */
const VERSION_INFO = Object.freeze({
  7: 0x07c94, 8: 0x085bc, 9: 0x09a99, 10: 0x0a4d3, 11: 0x0bbf6, 12: 0x0c762,
  13: 0x0d847, 14: 0x0e60d, 15: 0x0f928, 16: 0x10b78, 17: 0x1145d, 18: 0x12a17,
  19: 0x13532, 20: 0x149a6,
});

const GF_LOG = new Int16Array(256);
const GF_EXP = new Int16Array(512);
(function initGaloisField() {
  let x = 1;
  for (let i = 0; i < 255; i += 1) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i += 1) GF_EXP[i] = GF_EXP[i - 255];
}());

/**
 * @param {string} value
 * @returns {string}
 */
function escapeWifiField(value) {
  return value.replace(ESCAPE_RE, (char) => `\\${char}`);
}

/**
 * @param {WifiQrSecurityMode|string} security
 * @returns {string}
 */
function normalizeSecurityType(security) {
  const normalized = String(security ?? '').trim().toUpperCase();
  if (normalized === 'WPA2' || normalized === 'WPA3' || normalized === 'WPA2/WPA3' || normalized === 'WPA') {
    return 'WPA';
  }
  return 'WPA';
}

/**
 * Формирует строку WIFI:… для QR-кода (WPA-only; открытые сети не поддерживаются).
 * @param {WifiQrPayload} payload
 * @returns {string}
 */
export function buildWifiQrString({ security, ssid, password, hidden = false }) {
  const psk = typeof password === 'string' ? password : '';
  if (!psk) {
    throw new Error('Пароль обязателен для QR-кода Wi‑Fi');
  }
  const networkName = typeof ssid === 'string' ? ssid : '';
  if (!networkName) {
    throw new Error('Имя сети обязательно для QR-кода Wi‑Fi');
  }
  const type = normalizeSecurityType(security);
  const hiddenFlag = hidden ? 'true' : 'false';
  return `WIFI:T:${type};S:${escapeWifiField(networkName)};P:${escapeWifiField(psk)};H:${hiddenFlag};;`;
}

/**
 * @param {number} version
 * @returns {number}
 */
function matrixSizeForVersion(version) {
  return version * 4 + 17;
}

/**
 * @param {number} a
 * @param {number} b
 * @returns {number}
 */
function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

/**
 * @param {number[]} data
 * @param {number} ecCount
 * @returns {number[]}
 */
function reedSolomonEncode(data, ecCount) {
  /** @type {number[]} */
  const gen = [1];
  for (let i = 0; i < ecCount; i += 1) {
    /** @type {number[]} */
    const next = new Array(gen.length + 1).fill(0);
    for (let j = 0; j < gen.length; j += 1) {
      next[j] ^= gen[j];
      next[j + 1] ^= gfMul(gen[j], GF_EXP[i]);
    }
    for (let j = 0; j < gen.length; j += 1) gen[j] = next[j];
    gen.push(next[next.length - 1]);
  }
  /** @type {number[]} */
  const parity = new Array(ecCount).fill(0);
  for (const value of data) {
    const factor = value ^ parity[0];
    parity.shift();
    parity.push(0);
    for (let j = 0; j < ecCount; j += 1) parity[j] ^= gfMul(gen[j + 1], factor);
  }
  return parity;
}

/** Максимальная поддерживаемая версия QR (byte mode, EC=M). */
const MAX_QR_VERSION = 20;

/** @type {TextEncoder} */
const UTF8_ENCODER = new TextEncoder();

/**
 * Единственный способ получить байты payload — UTF-8 через TextEncoder.
 * @param {string} text
 * @returns {Uint8Array}
 */
function encodePayloadUtf8(text) {
  return UTF8_ENCODER.encode(text);
}

/**
 * @param {number} version
 * @returns {number}
 */
function byteModeCountFieldBits(version) {
  return version < 10 ? 8 : 16;
}

/**
 * Минимальное число data-codewords для byte-mode payload заданной длины в байтах.
 * @param {number} byteLength
 * @param {number} version
 * @returns {number}
 */
function requiredDataCodewordsForByteMode(byteLength, version) {
  const headerBits = 4 + byteModeCountFieldBits(version);
  const totalBits = headerBits + byteLength * 8 + 4;
  return Math.ceil(totalBits / 8);
}

/**
 * @param {number} byteLength
 * @returns {number}
 */
function selectVersionForByteLength(byteLength) {
  for (let version = 1; version <= MAX_QR_VERSION; version += 1) {
    if (byteLength > 255 && version < 10) continue;
    const capacity = DATA_CODEWORDS_M[version];
    if (requiredDataCodewordsForByteMode(byteLength, version) <= capacity) {
      return version;
    }
  }
  throw new Error('Данные слишком длинные для QR-кода');
}

/**
 * @param {Uint8Array} payloadBytes
 * @param {number} version
 * @returns {number[]}
 */
function buildDataCodewords(payloadBytes, version) {
  const byteLength = payloadBytes.length;
  const capacity = DATA_CODEWORDS_M[version];
  if (byteLength > 255 && version < 10) {
    throw new Error('Данные слишком длинные для QR-кода');
  }
  const required = requiredDataCodewordsForByteMode(byteLength, version);
  if (required > capacity) {
    throw new Error('Данные слишком длинные для QR-кода');
  }
  /** @type {number[]} */
  const bits = [];
  const pushBits = (value, count) => {
    for (let i = count - 1; i >= 0; i -= 1) bits.push((value >> i) & 1);
  };
  pushBits(0b0100, 4);
  pushBits(byteLength, byteModeCountFieldBits(version));
  for (let i = 0; i < byteLength; i += 1) pushBits(payloadBytes[i], 8);
  if (bits.length <= capacity * 8 - 4) pushBits(0, Math.min(4, capacity * 8 - bits.length));
  while (bits.length % 8 !== 0) bits.push(0);
  if (Math.ceil(bits.length / 8) > capacity) {
    throw new Error('Данные слишком длинные для QR-кода');
  }
  /** @type {number[]} */
  const codewords = [];
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j += 1) byte = (byte << 1) | bits[i + j];
    codewords.push(byte);
  }
  let pad = 0xec;
  while (codewords.length < capacity) {
    codewords.push(pad);
    pad = pad === 0xec ? 0x11 : 0xec;
  }
  return codewords;
}

/**
 * @param {number} version
 * @param {number[]} dataCodewords
 * @returns {number[]}
 */
function interleaveCodewords(version, dataCodewords) {
  const specs = BLOCK_SPECS_M[version];
  if (!specs) throw new Error(`Неподдерживаемая версия QR: ${version}`);
  /** @type {{ data: number[], ecLen: number }[]} */
  const blocks = [];
  let offset = 0;
  for (const [count, dataLen, ecLen] of specs) {
    for (let i = 0; i < count; i += 1) {
      const data = dataCodewords.slice(offset, offset + dataLen);
      blocks.push({ data, ecLen });
      offset += dataLen;
    }
  }
  /** @type {number[][]} */
  const encoded = blocks.map(({ data, ecLen }) => data.concat(reedSolomonEncode(data, ecLen)));
  /** @type {number[]} */
  const out = [];
  const maxData = Math.max(...encoded.map((b, i) => b.length - blocks[i].ecLen));
  const maxEc = Math.max(...blocks.map((b) => b.ecLen));
  for (let i = 0; i < maxData; i += 1) {
    for (let bi = 0; bi < encoded.length; bi += 1) {
      const dataLen = encoded[bi].length - blocks[bi].ecLen;
      if (i < dataLen) out.push(encoded[bi][i]);
    }
  }
  for (let i = 0; i < maxEc; i += 1) {
    for (let bi = 0; bi < encoded.length; bi += 1) {
      const ecLen = blocks[bi].ecLen;
      if (i < ecLen) out.push(encoded[bi][encoded[bi].length - ecLen + i]);
    }
  }
  return out;
}

/** @typedef {-1|null|boolean} MatrixCell */

/**
 * @param {number} version
 * @returns {MatrixCell[][]}
 */
function createMatrix(version) {
  const size = matrixSizeForVersion(version);
  return Array.from({ length: size }, () => new Array(size).fill(null));
}

/**
 * @param {MatrixCell[][]} matrix
 * @param {number} row
 * @param {number} col
 * @param {boolean} dark
 * @returns {void}
 */
function setModule(matrix, row, col, dark) {
  matrix[row][col] = dark;
}

/**
 * @param {MatrixCell[][]} matrix
 * @param {number} row
 * @param {number} col
 * @returns {void}
 */
function reserveModule(matrix, row, col) {
  matrix[row][col] = false;
}

/**
 * @param {MatrixCell[][]} matrix
 * @param {number} row
 * @param {number} col
 * @returns {void}
 */
function placeFinder(matrix, row, col) {
  for (let r = -1; r <= 7; r += 1) {
    for (let c = -1; c <= 7; c += 1) {
      const rr = row + r;
      const cc = col + c;
      if (rr < 0 || cc < 0 || rr >= matrix.length || cc >= matrix.length) continue;
      if (r >= 0 && r <= 6 && c >= 0 && c <= 6) {
        const border = r === 0 || r === 6 || c === 0 || c === 6;
        const center = r >= 2 && r <= 4 && c >= 2 && c <= 4;
        setModule(matrix, rr, cc, border || center);
      } else {
        reserveModule(matrix, rr, cc);
      }
    }
  }
}

/**
 * @param {MatrixCell[][]} matrix
 * @param {number} row
 * @param {number} col
 * @returns {void}
 */
function placeAlignment(matrix, row, col) {
  for (let r = -2; r <= 2; r += 1) {
    for (let c = -2; c <= 2; c += 1) {
      const border = Math.abs(r) === 2 || Math.abs(c) === 2;
      const center = r === 0 && c === 0;
      setModule(matrix, row + r, col + c, border || center);
    }
  }
}

/**
 * @param {MatrixCell[][]} matrix
 * @param {number} version
 * @returns {void}
 */
function embedStaticPatterns(matrix, version) {
  const size = matrix.length;
  placeFinder(matrix, 0, 0);
  placeFinder(matrix, 0, size - 7);
  placeFinder(matrix, size - 7, 0);
  const centers = ALIGNMENT_CENTERS[version] ?? [];
  for (const row of centers) {
    for (const col of centers) {
      if (matrix[row][col] !== null) continue;
      placeAlignment(matrix, row, col);
    }
  }
  for (let i = 8; i < size - 8; i += 1) {
    setModule(matrix, 6, i, i % 2 === 0);
    setModule(matrix, i, 6, i % 2 === 0);
  }
  setModule(matrix, size - 8, 8, true);
  reserveFormatInfoAreas(matrix);
}

/**
 * Резервирует ячейки под format info до размещения данных (иначе биты попадают в служебные поля).
 * @param {MatrixCell[][]} matrix
 * @returns {void}
 */
function reserveFormatInfoAreas(matrix) {
  const size = matrix.length;
  /** @type {Array<[number, number]>} */
  const coordsA = [];
  for (let i = 0; i < 6; i += 1) coordsA.push([8, i]);
  coordsA.push([8, 7], [8, 8], [7, 8]);
  for (let i = 5; i >= 0; i -= 1) coordsA.push([i, 8]);
  /** @type {Array<[number, number]>} */
  const coordsB = [];
  for (let i = 0; i < 7; i += 1) coordsB.push([size - 1 - i, 8]);
  for (let i = 0; i < 8; i += 1) coordsB.push([8, size - 8 + i]);
  for (const [row, col] of [...coordsA, ...coordsB]) {
    if (matrix[row][col] === null) {
      reserveModule(matrix, row, col);
    }
  }
}

/**
 * Помечает оставшиеся служебные ячейки как занятые, чтобы data bits туда не попали.
 * @param {MatrixCell[][]} matrix
 * @param {number} version
 * @returns {void}
 */
function reserveRemainingFunctionModules(matrix, version) {
  const size = matrix.length;
  for (let row = 0; row < size; row += 1) {
    for (let col = 0; col < size; col += 1) {
      if (matrix[row][col] === null && isFunctionModule(row, col, size, version)) {
        reserveModule(matrix, row, col);
      }
    }
  }
}

/**
 * @param {MatrixCell[][]} matrix
 * @param {number} version
 * @returns {void}
 */
function placeVersionInfo(matrix, version) {
  if (version < 7) return;
  const bits = VERSION_INFO[version];
  if (bits == null) return;
  const size = matrix.length;
  for (let i = 0; i < 18; i += 1) {
    const bit = ((bits >> i) & 1) === 1;
    const row = Math.floor(i / 3);
    const col = (i % 3) + size - 11;
    setModule(matrix, row, col, bit);
    setModule(matrix, col, row, bit);
  }
}

/**
 * @param {MatrixCell[][]} matrix
 * @param {number} formatBits
 * @returns {void}
 */
function applyFormatInfoToTemplate(matrix, formatBits) {
  const size = matrix.length;
  /** @type {Array<[number, number]>} */
  const coordsA = [];
  for (let i = 0; i < 6; i += 1) coordsA.push([8, i]);
  coordsA.push([8, 7], [8, 8], [7, 8]);
  for (let i = 5; i >= 0; i -= 1) coordsA.push([i, 8]);
  /** @type {Array<[number, number]>} */
  const coordsB = [];
  for (let i = 0; i < 7; i += 1) coordsB.push([size - 1 - i, 8]);
  for (let i = 0; i < 8; i += 1) coordsB.push([8, size - 8 + i]);
  for (let i = 0; i < 15; i += 1) {
    const bit = ((formatBits >> (14 - i)) & 1) === 1;
    setModule(matrix, coordsA[i][0], coordsA[i][1], bit);
    setModule(matrix, coordsB[i][0], coordsB[i][1], bit);
  }
}

/**
 * @param {MatrixCell[][]} matrix
 * @param {number[]} codewords
 * @param {number} mask
 * @returns {void}
 */
function placeDataBits(matrix, codewords, mask) {
  const size = matrix.length;
  let bitIndex = 0;
  let upward = true;
  for (let col = size - 1; col > 0; col -= 2) {
    if (col === 6) col -= 1;
    for (let i = 0; i < size; i += 1) {
      const row = upward ? size - 1 - i : i;
      for (let dc = 0; dc < 2; dc += 1) {
        const cc = col - dc;
        if (matrix[row][cc] !== null) continue;
        let bit = 0;
        if (bitIndex < codewords.length * 8) {
          bit = (codewords[Math.floor(bitIndex / 8)] >> (7 - (bitIndex % 8))) & 1;
        }
        let dark = bit === 1;
        if (maskPredicate(mask, row, cc)) dark = !dark;
        setModule(matrix, row, cc, dark);
        bitIndex += 1;
      }
    }
    upward = !upward;
  }
}

/**
 * @param {MatrixCell[][]} matrix
 * @returns {boolean[][]}
 */
function matrixToModules(matrix) {
  return matrix.map((row) => row.map((cell) => cell === true));
}

/**
 * @param {number} mask
 * @param {number} row
 * @param {number} col
 * @returns {boolean}
 */
function maskPredicate(mask, row, col) {
  switch (mask) {
    case 0: return ((row + col) & 1) === 0;
    case 1: return (row & 1) === 0;
    case 2: return col % 3 === 0;
    case 3: return (row + col) % 3 === 0;
    case 4: return ((Math.floor(row / 2) + Math.floor(col / 3)) & 1) === 0;
    case 5: return ((row * col) % 2 + (row * col) % 3) === 0;
    case 6: return (((row * col) % 2 + (row * col) % 3) & 1) === 0;
    case 7: return ((row * col) % 3 + (row + col) % 2) % 2 === 0;
    default: return false;
  }
}

/**
 * @param {number} row
 * @param {number} col
 * @param {number} size
 * @returns {boolean}
 */
function isInFinderArea(row, col, size) {
  if (row <= 8 && col <= 8) return true;
  if (row <= 8 && col >= size - 8) return true;
  if (row >= size - 8 && col <= 8) return true;
  return false;
}

/**
 * @param {number} row
 * @param {number} col
 * @param {number} size
 * @param {number} [version]
 * @returns {boolean}
 */
function isFunctionModule(row, col, size, version = 0) {
  if (isInFinderArea(row, col, size)) return true;
  if (row === 6 || col === 6) return true;
  if (row === size - 8 && col === 8) return true;
  return false;
}

/**
 * @param {boolean[][]} matrix
 * @returns {number}
 */
function maskPenaltyScore(matrix) {
  const size = matrix.length;
  let score = 0;
  const addRuns = (get) => {
    for (let i = 0; i < size; i += 1) {
      let run = 1;
      for (let j = 1; j < size; j += 1) {
        if (get(i, j) === get(i, j - 1)) run += 1;
        else {
          if (run >= 5) score += run - 2;
          run = 1;
        }
      }
      if (run >= 5) score += run - 2;
    }
  };
  addRuns((r, c) => matrix[r][c]);
  addRuns((r, c) => matrix[c][r]);
  for (let r = 0; r < size - 1; r += 1) {
    for (let c = 0; c < size - 1; c += 1) {
      const v = matrix[r][c];
      if (v === matrix[r][c + 1] && v === matrix[r + 1][c] && v === matrix[r + 1][c + 1]) score += 3;
    }
  }
  let dark = 0;
  for (const row of matrix) for (const cell of row) if (cell) dark += 1;
  score += Math.abs(Math.floor((dark * 100) / (size * size)) - 50) / 5;
  const pattern = [true, false, true, true, true, false, true, false, false, false, false];
  for (let r = 0; r < size; r += 1) {
    for (let c = 0; c <= size - 11; c += 1) {
      let match = true;
      for (let k = 0; k < 11; k += 1) {
        if (matrix[r][c + k] !== pattern[k]) {
          match = false;
          break;
        }
      }
      if (match) score += 40;
      match = true;
      for (let k = 0; k < 11; k += 1) {
        if (matrix[c + k][r] !== pattern[k]) {
          match = false;
          break;
        }
      }
      if (match) score += 40;
    }
  }
  return score;
}

/**
 * Строит булеву матрицу модулей QR-кода (ISO/IEC 18004, byte mode, EC=M).
 * @param {string} data
 * @returns {WifiQrMatrixResult}
 */
export function buildWifiQrMatrix(data) {
  const payloadBytes = encodePayloadUtf8(data);
  const version = selectVersionForByteLength(payloadBytes.length);
  const dataCodewords = buildDataCodewords(payloadBytes, version);
  const allCodewords = interleaveCodewords(version, dataCodewords);

  /** @type {{ mask: number, modules: boolean[][], score: number }|null} */
  let best = null;
  for (let mask = 0; mask < 8; mask += 1) {
    const template = createMatrix(version);
    embedStaticPatterns(template, version);
    placeVersionInfo(template, version);
    reserveRemainingFunctionModules(template, version);
    applyFormatInfoToTemplate(template, FORMAT_INFO_BITS_M[mask]);
    placeDataBits(template, allCodewords, mask);
    const modules = matrixToModules(template);
    const score = maskPenaltyScore(modules);
    if (!best || score < best.score) {
      best = { mask, modules, score };
    }
  }
  if (!best) throw new Error('Не удалось построить QR-код');
  return { version, mask: best.mask, modules: best.modules };
}

/**
 * Рисует QR-код в элементе canvas (экспорт изображения только через toDataURL).
 * @param {HTMLCanvasElement} canvas
 * @param {string} data
 * @param {{ moduleSize?: number, marginModules?: number, dark?: string, light?: string }} [options]
 * @returns {void}
 */
export function drawWifiQrCanvas(canvas, data, options = {}) {
  const { modules } = buildWifiQrMatrix(data);
  const moduleSize = options.moduleSize ?? 4;
  const marginModules = options.marginModules ?? 4;
  const dark = options.dark ?? '#000000';
  const light = options.light ?? '#ffffff';
  const size = modules.length + marginModules * 2;
  canvas.width = size * moduleSize;
  canvas.height = size * moduleSize;
  const ctx = canvas.getContext('2d');
  if (!ctx) throw new Error('Canvas 2D context недоступен');
  ctx.fillStyle = light;
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = dark;
  for (let row = 0; row < modules.length; row += 1) {
    for (let col = 0; col < modules[row].length; col += 1) {
      if (!modules[row][col]) continue;
      ctx.fillRect(
        (col + marginModules) * moduleSize,
        (row + marginModules) * moduleSize,
        moduleSize,
        moduleSize,
      );
    }
  }
}

/** Экспорт format info для контрактных тестов. */
export const QR_FORMAT_INFO_BITS_M = FORMAT_INFO_BITS_M;
