#[cfg(test)]
use testing::run_test;

use ed25519::fe::*;
use ed25519::constants::*;

// This is ge_p3 in the original source code
#[derive(Clone,Debug,PartialEq)]
pub struct Point {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
    pub t: FieldElement
}

impl Point {
  pub fn new() -> Point
  {
    Point {
      x: FieldElement::new(),
      y: FieldElement::new(),
      z: FieldElement::new(),
      t: FieldElement::new()
    }
  }

  #[cfg(test)]
  fn load_test_value(xs: &[u8]) -> Point {
    assert!(xs.len() == 160);
    Point {
      x: test_from_bytes(&xs[0..40]),
      y: test_from_bytes(&xs[40..80]),
      z: test_from_bytes(&xs[80..120]),
      t: test_from_bytes(&xs[120..])
    }
  }

  pub fn encode_to(&self, target: &mut [u8])
  {
    into_encoded_point(target, &self.x, &self.y, &self.z);
  }

  pub fn invert(&mut self)
  {
      let tmp = self.clone();
      fe_neg(&mut self.x, &tmp.x);
      fe_neg(&mut self.t, &tmp.t);
  }
}

const D: FieldElement = FieldElement {
    value: [-10913610, 13857413, -15372611, 6949391,   114729,
            -8787816,  -6275908, -3247719,  -18696448, -12055116]
};

const SQRTM1: FieldElement = FieldElement {
    value: [-32595792, -7943725,  9377950,  3500415, 12389472,
            -272473,   -25146209, -2005654, 326686,  11406482]
};

pub fn x25519_ge_frombytes_vartime(h: &mut Point, s: &[u8]) -> bool
{
  let mut u = FieldElement::new();
  let mut v = FieldElement::new();
  let mut v3 = FieldElement::new();
  let mut vxx = FieldElement::new();
  let mut check = FieldElement::new();
  let mut temp;

  fe_frombytes(&mut h.y, s);
  h.z.overwrite_with(&FieldElement::one());
  fe_square(&mut u, &h.y);
  fe_mul(&mut v, &u, &D);
  temp = u.clone();
  fe_sub(&mut u, &temp, &h.z); /* u = y^2-1 */
  temp = v.clone();
  fe_add(&mut v, &temp, &h.z); /* v = dy^2+1 */

  fe_square(&mut v3, &v);
  temp = v3.clone();
  fe_mul(&mut v3, &temp, &v); /* v3 = v^3 */
  fe_square(&mut h.x, &v3);
  temp = h.x.clone();
  fe_mul(&mut h.x, &temp, &v);
  temp = h.x.clone();
  fe_mul(&mut h.x, &temp, &u); /* x = uv^7 */

  temp = h.x.clone();
  fe_pow22523(&mut h.x, &temp); /* x = (uv^7)^((q-5)/8) */
  temp = h.x.clone();
  fe_mul(&mut h.x, &temp, &v3);
  temp = h.x.clone();
  fe_mul(&mut h.x, &temp, &u); /* x = uv^3(uv^7)^((q-5)/8) */

  fe_square(&mut vxx, &h.x);
  temp = vxx.clone();
  fe_mul(&mut vxx, &temp, &v);
  fe_sub(&mut check, &vxx, &u); /* vx^2-u */
  if fe_isnonzero(&check) {
    fe_add(&mut check, &vxx, &u); /* vx^2+u */
    if fe_isnonzero(&check) {
      return false;
    }
    temp = h.x.clone();
    fe_mul(&mut h.x, &temp, &SQRTM1);
  }

  if fe_isnegative(&h.x) != ((s[31] >> 7) == 1) {
    temp = h.x.clone();
    fe_neg(&mut h.x, &temp);
  }

  fe_mul(&mut h.t, &h.x, &h.y);
  return true;
}

#[cfg(test)]
#[test]
fn from_bytes_vartime() {
    let fname = "testdata/ed25519/fbv.test";
    run_test(fname.to_string(), 2, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negc, cbytes) = case.get("c").unwrap();

        assert!(!nega && !negc);
        let target = Point::load_test_value(&cbytes);
        let mut mine = Point::new();
        x25519_ge_frombytes_vartime(&mut mine, &abytes);
        assert_eq!(target, mine);
    });
}

fn ge_p3_0(h: &mut Point)
{
    h.x.overwrite_with(&FieldElement::zero());
    h.y.overwrite_with(&FieldElement::one());
    h.z.overwrite_with(&FieldElement::one());
    h.t.overwrite_with(&FieldElement::zero());
}

#[derive(Debug,PartialEq)]
pub struct Point2 {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
}

impl Point2 {
  pub fn new() -> Point2
  {
    Point2 {
      x: FieldElement::new(),
      y: FieldElement::new(),
      z: FieldElement::new()
    }
  }

  #[cfg(test)]
  fn load_test_value(xs: &[u8]) -> Point2 {
    assert!(xs.len() == 120);
    Point2 {
      x: test_from_bytes(&xs[0..40]),
      y: test_from_bytes(&xs[40..80]),
      z: test_from_bytes(&xs[80..120]),
    }
  }

  pub fn encode_to(&self, target: &mut [u8])
  {
    into_encoded_point(target, &self.x, &self.y, &self.z);
  }
}

fn ge_p2_0(h: &mut Point2)
{
    h.x.overwrite_with(&FieldElement::zero());
    h.y.overwrite_with(&FieldElement::one());
    h.z.overwrite_with(&FieldElement::one());
}

fn ge_p3_to_p2(r: &mut Point2, p: &Point)
{
    r.x.overwrite_with(&p.x);
    r.y.overwrite_with(&p.y);
    r.z.overwrite_with(&p.z);
}

#[derive(Debug,PartialEq)]
struct PointP1P1 {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    t: FieldElement
}

impl PointP1P1 {
  fn new() -> PointP1P1
  {
    PointP1P1 {
      x: FieldElement::new(),
      y: FieldElement::new(),
      z: FieldElement::new(),
      t: FieldElement::new(),
    }
  }

  #[cfg(test)]
  fn load_test_value(xs: &[u8]) -> PointP1P1 {
    assert!(xs.len() == 160);
    PointP1P1 {
      x: test_from_bytes(&xs[0..40]),
      y: test_from_bytes(&xs[40..80]),
      z: test_from_bytes(&xs[80..120]),
      t: test_from_bytes(&xs[120..])
    }
  }
}

#[derive(Debug,PartialEq)]
struct Cached {
  yplusx:  FieldElement,
  yminusx: FieldElement,
  z:       FieldElement,
  t2d:     FieldElement
}

impl Cached
{
  fn new() -> Cached
  {
    Cached {
      yplusx: FieldElement::new(),
      yminusx: FieldElement::new(),
      z: FieldElement::new(),
      t2d: FieldElement::new()
    }
  }

  #[cfg(test)]
  fn load_test_value(xs: &[u8]) -> Cached {
    assert!(xs.len() == 160);
    Cached {
      yplusx: test_from_bytes(&xs[0..40]),
      yminusx: test_from_bytes(&xs[40..80]),
      z: test_from_bytes(&xs[80..120]),
      t2d: test_from_bytes(&xs[120..])
    }
  }
}

const D2: FieldElement = FieldElement {
    value: [-21827239, -5839606,  -30745221, 13898782, 229458,
            15978800,  -12551817, -6495438,  29715968, 9444199]
};

fn x25519_ge_p3_to_cached(r: &mut Cached, p: &Point)
{
  fe_add(&mut r.yplusx, &p.y, &p.x);
  fe_sub(&mut r.yminusx, &p.y, &p.x);
  r.z.overwrite_with(&p.z);
  fe_mul(&mut r.t2d, &p.t, &D2);
}

/* r = p */
fn x25519_ge_p1p1_to_p2(r: &mut Point2, p: &PointP1P1)
{
  fe_mul(&mut r.x, &p.x, &p.t);
  fe_mul(&mut r.y, &p.y, &p.z);
  fe_mul(&mut r.z, &p.z, &p.t);
}

/* r = p */
fn x25519_ge_p1p1_to_p3(r: &mut Point, p: &PointP1P1)
{
  fe_mul(&mut r.x, &p.x, &p.t);
  fe_mul(&mut r.y, &p.y, &p.z);
  fe_mul(&mut r.z, &p.z, &p.t);
  fe_mul(&mut r.t, &p.x, &p.y);
}

#[cfg(test)]
#[test]
fn conversion() {
    let fname = "testdata/ed25519/conversion.test";
    run_test(fname.to_string(), 6, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negc, cbytes) = case.get("c").unwrap();
        let (negt, tbytes) = case.get("t").unwrap();
        let (nego, obytes) = case.get("o").unwrap();
        let (negd, dbytes) = case.get("d").unwrap();
        let (negb, bbytes) = case.get("b").unwrap();

        let a = Point::load_test_value(&abytes);
        let c = Cached::load_test_value(&cbytes);
        let t = Point2::load_test_value(&tbytes);
        let o = PointP1P1::load_test_value(&obytes);
        let d = Point2::load_test_value(&dbytes);
        let b = Point::load_test_value(&bbytes);

        assert!(!nega && !negc && !negt && !nego && !negd && !negb);

        let mut myc = Cached::new();
        x25519_ge_p3_to_cached(&mut myc, &a);
        assert_eq!(myc, c);

        let mut myt = Point2::new();
        ge_p3_to_p2(&mut myt, &a);
        assert_eq!(myt, t);

        let mut myo = PointP1P1::new();
        ge_p3_dbl(&mut myo, &a);
        assert_eq!(myo, o);

        let mut myd = Point2::new();
        x25519_ge_p1p1_to_p2(&mut myd, &o);
        assert_eq!(myd, d);

        let mut myb = Point::new();
        x25519_ge_p1p1_to_p3(&mut myb, &o);
        assert_eq!(myb, b);
    });
}

/* r = 2 * p */
fn ge_p2_dbl(r: &mut PointP1P1, p: &Point2)
{
  let mut t0 = FieldElement::new();

  fe_square(&mut r.x, &p.x);
  fe_square(&mut r.z, &p.y);
  fe_sq2(&mut r.t, &p.z);
  fe_add(&mut r.y, &p.x, &p.y);
  fe_square(&mut t0, &r.y);
  fe_add(&mut r.y, &r.z, &r.x);
  let mut temp = r.z.clone();
  fe_sub(&mut r.z, &temp, &r.x);
  fe_sub(&mut r.x, &t0,  &r.y);
  temp = r.t.clone();
  fe_sub(&mut r.t, &temp, &r.z);
}

/* r = 2 * p */
fn ge_p3_dbl(r: &mut PointP1P1, p: &Point)
{
  let mut q = Point2::new();
  ge_p3_to_p2(&mut q, p);
  ge_p2_dbl(r, &q);
}

#[cfg(test)]
#[test]
fn double() {
    let fname = "testdata/ed25519/pt_double.test";
    run_test(fname.to_string(), 4, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negb, bbytes) = case.get("b").unwrap();
        let (negc, cbytes) = case.get("c").unwrap();
        let (negd, dbytes) = case.get("d").unwrap();

        assert!(!nega && !negb && !negc && !negd);
        let a = Point::load_test_value(abytes);
        let b = PointP1P1::load_test_value(bbytes);
        let c = Point2::load_test_value(cbytes);
        let d = PointP1P1::load_test_value(dbytes);

        let mut mine = PointP1P1::new();
        ge_p3_dbl(&mut mine, &a);
        assert_eq!(mine, b);
        ge_p2_dbl(&mut mine, &c);
        assert_eq!(mine, d);
    });
}

/* r = p + q */
fn ge_madd(r: &mut PointP1P1, p: &Point, q: &Precomp)
{
  let mut t0 = FieldElement::new();
  let mut temp;

  fe_add(&mut r.x, &p.y,    &p.x);
  fe_sub(&mut r.y, &p.y,    &p.x);
  fe_mul(&mut r.z, &r.x,    &q.yplusx);
  temp = r.y.clone();
  fe_mul(&mut r.y, &temp,   &q.yminusx);
  fe_mul(&mut r.t, &q.xy2d, &p.t);
  fe_add(&mut t0,  &p.z,    &p.z);
  fe_sub(&mut r.x, &r.z,    &r.y);
  temp = r.y.clone();
  fe_add(&mut r.y, &r.z,    &temp);
  fe_add(&mut r.z, &t0,     &r.t);
  temp = r.t.clone();
  fe_sub(&mut r.t, &t0,     &temp);
}

/* r = p - q */
fn ge_msub(r: &mut PointP1P1, p: &Point, q: &Precomp)
{
  let mut t0 = FieldElement::new();
  let mut temp;

  fe_add(&mut r.x, &p.y,    &p.x);
  fe_sub(&mut r.y, &p.y,    &p.x);
  fe_mul(&mut r.z, &r.x,    &q.yminusx);
  temp = r.y.clone();
  fe_mul(&mut r.y, &temp,   &q.yplusx);
  fe_mul(&mut r.t, &q.xy2d, &p.t);
  fe_add(&mut t0,  &p.z,    &p.z);
  fe_sub(&mut r.x, &r.z,    &r.y);
  temp = r.y.clone();
  fe_add(&mut r.y, &r.z,    &temp);
  fe_sub(&mut r.z, &t0,     &r.t);
  temp = r.t.clone();
  fe_add(&mut r.t, &t0,     &temp);
}

#[cfg(test)]
#[test]
fn maddsub() {
    let fname = "testdata/ed25519/maddsub.test";
    run_test(fname.to_string(), 4, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negb, bbytes) = case.get("b").unwrap();
        let (negc, cbytes) = case.get("c").unwrap();
        let (negd, dbytes) = case.get("d").unwrap();

        assert!(!nega && !negb && !negc && !negd);
        let a = Point::load_test_value(abytes);
        let b = PointP1P1::load_test_value(bbytes);
        let c = Precomp::load_test_value(cbytes);
        let d = PointP1P1::load_test_value(dbytes);

        let mut mine = PointP1P1::new();
        ge_madd(&mut mine, &a, &c);
        assert_eq!(mine, b);
        ge_msub(&mut mine, &a, &c);
        assert_eq!(mine, d);
    });
}

/* r = p + q */
fn x25519_ge_add(r: &mut PointP1P1, p: &Point, q: &Cached)
{
  let mut t0 = FieldElement::new();
  let mut temp;

  fe_add(&mut r.x, &p.y,   &p.x);
  fe_sub(&mut r.y, &p.y,   &p.x);
  fe_mul(&mut r.z, &r.x,   &q.yplusx);
  temp = r.y.clone();
  fe_mul(&mut r.y, &temp,  &q.yminusx);
  fe_mul(&mut r.t, &q.t2d, &p.t);
  fe_mul(&mut r.x, &p.z,   &q.z);
  fe_add(&mut t0,  &r.x,   &r.x);
  fe_sub(&mut r.x, &r.z,   &r.y);
  temp = r.y.clone();
  fe_add(&mut r.y, &r.z,   &temp);
  fe_add(&mut r.z, &t0,    &r.t);
  temp = r.t.clone();
  fe_sub(&mut r.t, &t0,    &temp);
}

/* r = p - q */
fn x25519_ge_sub(r: &mut PointP1P1, p: &Point, q: &Cached)
{
  let mut t0 = FieldElement::new();
  let mut temp;

  fe_add(&mut r.x, &p.y,   &p.x);
  fe_sub(&mut r.y, &p.y,   &p.x);
  fe_mul(&mut r.z, &r.x,   &q.yminusx);
  temp = r.y.clone();
  fe_mul(&mut r.y, &temp,  &q.yplusx);
  fe_mul(&mut r.t, &q.t2d, &p.t);
  fe_mul(&mut r.x, &p.z,   &q.z);
  fe_add(&mut t0,  &r.x,   &r.x);
  fe_sub(&mut r.x, &r.z,   &r.y);
  temp = r.y.clone();
  fe_add(&mut r.y, &r.z,   &temp);
  fe_sub(&mut r.z, &t0,    &r.t);
  temp = r.t.clone();
  fe_add(&mut r.t, &t0,    &temp);
}

#[cfg(test)]
#[test]
fn addsub() {
    let fname = "testdata/ed25519/ptaddsub.test";
    run_test(fname.to_string(), 4, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negb, bbytes) = case.get("b").unwrap();
        let (negc, cbytes) = case.get("c").unwrap();
        let (negd, dbytes) = case.get("d").unwrap();

        assert!(!nega && !negb && !negc && !negd);
        let a = Point::load_test_value(abytes);
        let b = PointP1P1::load_test_value(bbytes);
        let c = Cached::load_test_value(cbytes);
        let d = PointP1P1::load_test_value(dbytes);

        let mut mine = PointP1P1::new();
        x25519_ge_add(&mut mine, &a, &c);
        assert_eq!(mine, b);
        x25519_ge_sub(&mut mine, &a, &c);
        assert_eq!(mine, d);
    });
}

fn equal(b: i8, c: i8) -> bool
{
  let ub = b;
  let uc = c;
  let x = ub ^ uc;  /* 0: yes; 1..255: no */
  (x == 0)
}

fn cmov(t: &mut Precomp, u: &Precomp, b: bool)
{
  fe_cmov(&mut t.yplusx, &u.yplusx, b);
  fe_cmov(&mut t.yminusx, &u.yminusx, b);
  fe_cmov(&mut t.xy2d, &u.xy2d, b);
}

fn negative(b: i8) -> u8
{
  let mut x = b as u32;
  x >>= 31; /* 1: yes; 0: no */
  x as u8
}

fn table_select(t: &mut Precomp, pos: i32, b: i8)
{
  let mut minust = Precomp::new();
  let bnegative = negative(b);
  let babs = b - (((-(bnegative as i8)) & b) << 1);

  ge_precomp_0(t);
  cmov(t, &K25519_PRECOMP[pos as usize][0], equal(babs, 1));
  cmov(t, &K25519_PRECOMP[pos as usize][1], equal(babs, 2));
  cmov(t, &K25519_PRECOMP[pos as usize][2], equal(babs, 3));
  cmov(t, &K25519_PRECOMP[pos as usize][3], equal(babs, 4));
  cmov(t, &K25519_PRECOMP[pos as usize][4], equal(babs, 5));
  cmov(t, &K25519_PRECOMP[pos as usize][5], equal(babs, 6));
  cmov(t, &K25519_PRECOMP[pos as usize][6], equal(babs, 7));
  cmov(t, &K25519_PRECOMP[pos as usize][7], equal(babs, 8));
  minust.yplusx.overwrite_with(&t.yminusx);
  minust.yminusx.overwrite_with(&t.yplusx);
  fe_neg(&mut minust.xy2d, &t.xy2d);
  cmov(t, &minust, bnegative != 0);
}

/* h = a * B
 * where a = a[0]+256*a[1]+...+256^31 a[31]
 * B is the Ed25519 base point (x,4/5) with x positive.
 *
 * Preconditions:
 *   a[31] <= 127 */
pub fn x25519_ge_scalarmult_base(h: &mut Point, a: &[u8])
{
  let mut e: [i8; 64] = [0; 64];
  for i in 0..32 {
    e[2 * i + 0] = ((a[i] >> 0) & 15) as i8;
    e[2 * i + 1] = ((a[i] >> 4) & 15) as i8;
  }
  /* each e[i] is between 0 and 15 */
  /* e[63] is between 0 and 7 */

  let mut carry = 0;
  for i in 0..63 {
    e[i] += carry;
    carry = e[i] + 8;
    carry >>= 4;
    e[i] -= carry << 4;
  }
  e[63] += carry;
  /* each e[i] is between -8 and 8 */

  let mut r = PointP1P1::new();
  let mut s = Point2::new();
  let mut t = Precomp::new();

  ge_p3_0(h);
  for i in &[1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,47,49,51,53,55,57,59,61,63] {
    table_select(&mut t, *i / 2, e[*i as usize]);
    ge_madd(&mut r, &h, &t);
    x25519_ge_p1p1_to_p3(h, &r);
  }

  ge_p3_dbl(&mut r, &h);
  x25519_ge_p1p1_to_p2(&mut s, &r);
  ge_p2_dbl(&mut r, &s);
  x25519_ge_p1p1_to_p2(&mut s, &r);
  ge_p2_dbl(&mut r, &s);
  x25519_ge_p1p1_to_p2(&mut s, &r);
  ge_p2_dbl(&mut r, &s);
  x25519_ge_p1p1_to_p3(h, &r);

  for i in &[0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38,40,42,44,46,48,50,52,54,56,58,60,62] {
    table_select(&mut t, *i / 2, e[*i as usize]);
    ge_madd(&mut r, &h, &t);
    x25519_ge_p1p1_to_p3(h, &r);
  }
}

#[cfg(test)]
#[test]
fn scalarmult_base() {
    let fname = "testdata/ed25519/scalar_mult.test";
    run_test(fname.to_string(), 2, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negb, bbytes) = case.get("b").unwrap();

        assert!(!nega && !negb);
        let     b    = Point::load_test_value(bbytes);
        let mut mine = Point::new();
        x25519_ge_scalarmult_base(&mut mine, abytes);
        assert_eq!(mine, b);
    });
}

fn slide(r: &mut [i8], a: &[u8])
{
  for i in 0..256 {
    r[i] = (1 & (a[i >> 3] >> (i & 7))) as i8;
  }

  for i in 0..256 {
    if r[i] != 0 {
      let mut b = 1;
      while (b <= 6) && ((i + b) < 256) {
        if r[i + b] != 0 {
          if r[i] + (r[i + b] << b) <= 15 {
            r[i] += r[i + b] << b;
            r[i + b] = 0;
          } else if r[i] - (r[i + b] << b) >= -15 {
            r[i] -= r[i + b] << b;
            for k in (i+b)..256 {
              if r[k] == 0 {
                r[k] = 1;
                break;
              }
              r[k] = 0;
            }
          } else {
            break;
          }
        }
        b += 1;
      }
    }
  }
}

#[cfg(test)]
#[test]
fn helper_slide() {
    let fname = "testdata/ed25519/slide.test";
    run_test(fname.to_string(), 2, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negb, bbytes) = case.get("b").unwrap();

        assert!(!nega && !negb);
        let mut mine = [0; 256];
        slide(&mut mine, &abytes);
        for i in 0..256 {
          assert_eq!(mine[i], bbytes[i] as i8);
        }
    });
}

/* r = a * A + b * B
 * where a = a[0]+256*a[1]+...+256^31 a[31].
 * and b = b[0]+256*b[1]+...+256^31 b[31].
 * B is the Ed25519 base point (x,4/5) with x positive. */
#[allow(non_snake_case)]
pub fn ge_double_scalarmult_vartime(r: &mut Point2, a: &[u8], A: &Point, b: &[u8])
{
  let mut aslide: [i8; 256] = [0; 256];
  let mut bslide: [i8; 256] = [0; 256];
  #[allow(non_snake_case)]
  let mut Ai: [Cached; 8] = [Cached::new(), Cached::new(), Cached::new(), Cached::new(),
                             Cached::new(), Cached::new(), Cached::new(), Cached::new()];
  let mut t = PointP1P1::new();
  let mut u = Point::new();
  #[allow(non_snake_case)]
  let mut A2 = Point::new();

  slide(&mut aslide, &a);
  slide(&mut bslide, &b);

  x25519_ge_p3_to_cached(&mut Ai[0], &A);
  ge_p3_dbl(&mut t, &A);
  x25519_ge_p1p1_to_p3(&mut A2, &t);
  x25519_ge_add(&mut t, &A2, &Ai[0]);
  x25519_ge_p1p1_to_p3(&mut u, &t);
  x25519_ge_p3_to_cached(&mut Ai[1], &u);
  x25519_ge_add(&mut t, &A2, &Ai[1]);
  x25519_ge_p1p1_to_p3(&mut u, &t);
  x25519_ge_p3_to_cached(&mut Ai[2], &u);
  x25519_ge_add(&mut t, &A2, &Ai[2]);
  x25519_ge_p1p1_to_p3(&mut u, &t);
  x25519_ge_p3_to_cached(&mut Ai[3], &u);
  x25519_ge_add(&mut t, &A2, &Ai[3]);
  x25519_ge_p1p1_to_p3(&mut u, &t);
  x25519_ge_p3_to_cached(&mut Ai[4], &u);
  x25519_ge_add(&mut t, &A2, &Ai[4]);
  x25519_ge_p1p1_to_p3(&mut u, &t);
  x25519_ge_p3_to_cached(&mut Ai[5], &u);
  x25519_ge_add(&mut t, &A2, &Ai[5]);
  x25519_ge_p1p1_to_p3(&mut u, &t);
  x25519_ge_p3_to_cached(&mut Ai[6], &u);
  x25519_ge_add(&mut t, &A2, &Ai[6]);
  x25519_ge_p1p1_to_p3(&mut u, &t);
  x25519_ge_p3_to_cached(&mut Ai[7], &u);

  ge_p2_0(r);

  let mut i: i32 = 255;
  loop {
    if (aslide[i as usize] != 0) || (bslide[i as usize] != 0) {
      break;
    }
    i -= 1;
    if i < 0 {
      break;
    }
  }

  while i >= 0 {
    ge_p2_dbl(&mut t, r);

    if aslide[i as usize] > 0 {
      x25519_ge_p1p1_to_p3(&mut u, &t);
      let idx = (aslide[i as usize] / 2) as usize;
      x25519_ge_add(&mut t, &u, &Ai[idx]);
    } else if aslide[i as usize] < 0 {
      x25519_ge_p1p1_to_p3(&mut u, &t);
      let idx = ((-aslide[i as usize]) / 2) as usize;
      x25519_ge_sub(&mut t, &u, &Ai[idx]);
    }

    if bslide[i as usize] > 0 {
      x25519_ge_p1p1_to_p3(&mut u, &t);
      let idx = (bslide[i as usize] / 2) as usize;
      ge_madd(&mut t, &u, &BI[idx]);
    } else if bslide[i as usize] < 0 {
      x25519_ge_p1p1_to_p3(&mut u, &t);
      let idx = ((-bslide[i as usize]) / 2) as usize;
      ge_msub(&mut t, &u, &BI[idx]);
    }

    x25519_ge_p1p1_to_p2(r, &t);
    i -= 1;
  }
}

#[cfg(test)]
#[test]
fn double_scalarmult() {
    let fname = "testdata/ed25519/scalar_mult_gen.test";
    run_test(fname.to_string(), 4, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negb, bbytes) = case.get("b").unwrap();
        let (negc, cbytes) = case.get("c").unwrap();
        let (negd, dbytes) = case.get("d").unwrap();

        assert!(!nega && !negb && !negc && !negd);
        let b = Point::load_test_value(bbytes);
        let d = Point2::load_test_value(dbytes);
        let mut mine = Point2::new();
        ge_double_scalarmult_vartime(&mut mine, &abytes, &b, &cbytes);
        assert_eq!(mine, d);
    });
}

/* The set of scalars is \Z/l
 * where l = 2^252 + 27742317777372353535851937790883648493. */

/* Input:
 *   s[0]+256*s[1]+...+256^63*s[63] = s
 *
 * Output:
 *   s[0]+256*s[1]+...+256^31*s[31] = s mod l
 *   where l = 2^252 + 27742317777372353535851937790883648493.
 *   Overwrites s in place. */
pub fn x25519_sc_reduce(s: &mut [u8])
{
  let mut s0  : i64 = 2097151 & load3(s) as i64;
  let mut s1  : i64 = 2097151 & (load4(&s[2..]) >> 5) as i64;
  let mut s2  : i64 = 2097151 & (load3(&s[5..]) >> 2) as i64;
  let mut s3  : i64 = 2097151 & (load4(&s[7..]) >> 7) as i64;
  let mut s4  : i64 = 2097151 & (load4(&s[10..]) >> 4) as i64;
  let mut s5  : i64 = 2097151 & (load3(&s[13..]) >> 1) as i64;
  let mut s6  : i64 = 2097151 & (load4(&s[15..]) >> 6) as i64;
  let mut s7  : i64 = 2097151 & (load3(&s[18..]) >> 3) as i64;
  let mut s8  : i64 = 2097151 & load3(&s[21..]) as i64;
  let mut s9  : i64 = 2097151 & (load4(&s[23..]) >> 5) as i64;
  let mut s10 : i64 = 2097151 & (load3(&s[26..]) >> 2) as i64;
  let mut s11 : i64 = 2097151 & (load4(&s[28..]) >> 7) as i64;
  let mut s12 : i64 = 2097151 & (load4(&s[31..]) >> 4) as i64;
  let mut s13 : i64 = 2097151 & (load3(&s[34..]) >> 1) as i64;
  let mut s14 : i64 = 2097151 & (load4(&s[36..]) >> 6) as i64;
  let mut s15 : i64 = 2097151 & (load3(&s[39..]) >> 3) as i64;
  let mut s16 : i64 = 2097151 & load3(&s[42..]) as i64;
  let mut s17 : i64 = 2097151 & (load4(&s[44..]) >> 5) as i64;
  let     s18 : i64 = 2097151 & (load3(&s[47..]) >> 2) as i64;
  let     s19 : i64 = 2097151 & (load4(&s[49..]) >> 7) as i64;
  let     s20 : i64 = 2097151 & (load4(&s[52..]) >> 4) as i64;
  let     s21 : i64 = 2097151 & (load3(&s[55..]) >> 1) as i64;
  let     s22 : i64 = 2097151 & (load4(&s[57..]) >> 6) as i64;
  let     s23 : i64 = (load4(&s[60..]) >> 3) as i64 as i64;
  let mut carry0 : i64;
  let mut carry1 : i64;
  let mut carry2 : i64;
  let mut carry3 : i64;
  let mut carry4 : i64;
  let mut carry5 : i64;
  let mut carry6 : i64;
  let mut carry7 : i64;
  let mut carry8 : i64;
  let mut carry9 : i64;
  let mut carry10 : i64;
  let mut carry11 : i64;
  let     carry12 : i64;
  let     carry13 : i64;
  let     carry14 : i64;
  let     carry15 : i64;
  let     carry16 : i64;

  s11 += s23 * 666643;
  s12 += s23 * 470296;
  s13 += s23 * 654183;
  s14 -= s23 * 997805;
  s15 += s23 * 136657;
  s16 -= s23 * 683901;
  //s23 = 0;

  s10 += s22 * 666643;
  s11 += s22 * 470296;
  s12 += s22 * 654183;
  s13 -= s22 * 997805;
  s14 += s22 * 136657;
  s15 -= s22 * 683901;
  //s22 = 0;

  s9 += s21 * 666643;
  s10 += s21 * 470296;
  s11 += s21 * 654183;
  s12 -= s21 * 997805;
  s13 += s21 * 136657;
  s14 -= s21 * 683901;
  //s21 = 0;

  s8 += s20 * 666643;
  s9 += s20 * 470296;
  s10 += s20 * 654183;
  s11 -= s20 * 997805;
  s12 += s20 * 136657;
  s13 -= s20 * 683901;
  //s20 = 0;

  s7 += s19 * 666643;
  s8 += s19 * 470296;
  s9 += s19 * 654183;
  s10 -= s19 * 997805;
  s11 += s19 * 136657;
  s12 -= s19 * 683901;
  //s19 = 0;

  s6 += s18 * 666643;
  s7 += s18 * 470296;
  s8 += s18 * 654183;
  s9 -= s18 * 997805;
  s10 += s18 * 136657;
  s11 -= s18 * 683901;
  //s18 = 0;

  carry6 = (s6 + (1 << 20)) >> 21;
  s7 += carry6;
  s6 -= carry6 << 21;
  carry8 = (s8 + (1 << 20)) >> 21;
  s9 += carry8;
  s8 -= carry8 << 21;
  carry10 = (s10 + (1 << 20)) >> 21;
  s11 += carry10;
  s10 -= carry10 << 21;
  carry12 = (s12 + (1 << 20)) >> 21;
  s13 += carry12;
  s12 -= carry12 << 21;
  carry14 = (s14 + (1 << 20)) >> 21;
  s15 += carry14;
  s14 -= carry14 << 21;
  carry16 = (s16 + (1 << 20)) >> 21;
  s17 += carry16;
  s16 -= carry16 << 21;

  carry7 = (s7 + (1 << 20)) >> 21;
  s8 += carry7;
  s7 -= carry7 << 21;
  carry9 = (s9 + (1 << 20)) >> 21;
  s10 += carry9;
  s9 -= carry9 << 21;
  carry11 = (s11 + (1 << 20)) >> 21;
  s12 += carry11;
  s11 -= carry11 << 21;
  carry13 = (s13 + (1 << 20)) >> 21;
  s14 += carry13;
  s13 -= carry13 << 21;
  carry15 = (s15 + (1 << 20)) >> 21;
  s16 += carry15;
  s15 -= carry15 << 21;

  s5 += s17 * 666643;
  s6 += s17 * 470296;
  s7 += s17 * 654183;
  s8 -= s17 * 997805;
  s9 += s17 * 136657;
  s10 -= s17 * 683901;
  //s17 = 0;

  s4 += s16 * 666643;
  s5 += s16 * 470296;
  s6 += s16 * 654183;
  s7 -= s16 * 997805;
  s8 += s16 * 136657;
  s9 -= s16 * 683901;
  //s16 = 0;

  s3 += s15 * 666643;
  s4 += s15 * 470296;
  s5 += s15 * 654183;
  s6 -= s15 * 997805;
  s7 += s15 * 136657;
  s8 -= s15 * 683901;
  //s15 = 0;

  s2 += s14 * 666643;
  s3 += s14 * 470296;
  s4 += s14 * 654183;
  s5 -= s14 * 997805;
  s6 += s14 * 136657;
  s7 -= s14 * 683901;
  //s14 = 0;

  s1 += s13 * 666643;
  s2 += s13 * 470296;
  s3 += s13 * 654183;
  s4 -= s13 * 997805;
  s5 += s13 * 136657;
  s6 -= s13 * 683901;
  //s13 = 0;

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = (s0 + (1 << 20)) >> 21;
  s1 += carry0;
  s0 -= carry0 << 21;
  carry2 = (s2 + (1 << 20)) >> 21;
  s3 += carry2;
  s2 -= carry2 << 21;
  carry4 = (s4 + (1 << 20)) >> 21;
  s5 += carry4;
  s4 -= carry4 << 21;
  carry6 = (s6 + (1 << 20)) >> 21;
  s7 += carry6;
  s6 -= carry6 << 21;
  carry8 = (s8 + (1 << 20)) >> 21;
  s9 += carry8;
  s8 -= carry8 << 21;
  carry10 = (s10 + (1 << 20)) >> 21;
  s11 += carry10;
  s10 -= carry10 << 21;

  carry1 = (s1 + (1 << 20)) >> 21;
  s2 += carry1;
  s1 -= carry1 << 21;
  carry3 = (s3 + (1 << 20)) >> 21;
  s4 += carry3;
  s3 -= carry3 << 21;
  carry5 = (s5 + (1 << 20)) >> 21;
  s6 += carry5;
  s5 -= carry5 << 21;
  carry7 = (s7 + (1 << 20)) >> 21;
  s8 += carry7;
  s7 -= carry7 << 21;
  carry9 = (s9 + (1 << 20)) >> 21;
  s10 += carry9;
  s9 -= carry9 << 21;
  carry11 = (s11 + (1 << 20)) >> 21;
  s12 += carry11;
  s11 -= carry11 << 21;

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = s0 >> 21;
  s1 += carry0;
  s0 -= carry0 << 21;
  carry1 = s1 >> 21;
  s2 += carry1;
  s1 -= carry1 << 21;
  carry2 = s2 >> 21;
  s3 += carry2;
  s2 -= carry2 << 21;
  carry3 = s3 >> 21;
  s4 += carry3;
  s3 -= carry3 << 21;
  carry4 = s4 >> 21;
  s5 += carry4;
  s4 -= carry4 << 21;
  carry5 = s5 >> 21;
  s6 += carry5;
  s5 -= carry5 << 21;
  carry6 = s6 >> 21;
  s7 += carry6;
  s6 -= carry6 << 21;
  carry7 = s7 >> 21;
  s8 += carry7;
  s7 -= carry7 << 21;
  carry8 = s8 >> 21;
  s9 += carry8;
  s8 -= carry8 << 21;
  carry9 = s9 >> 21;
  s10 += carry9;
  s9 -= carry9 << 21;
  carry10 = s10 >> 21;
  s11 += carry10;
  s10 -= carry10 << 21;
  carry11 = s11 >> 21;
  s12 += carry11;
  s11 -= carry11 << 21;

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  //s12 = 0;

  carry0 = s0 >> 21;
  s1 += carry0;
  s0 -= carry0 << 21;
  carry1 = s1 >> 21;
  s2 += carry1;
  s1 -= carry1 << 21;
  carry2 = s2 >> 21;
  s3 += carry2;
  s2 -= carry2 << 21;
  carry3 = s3 >> 21;
  s4 += carry3;
  s3 -= carry3 << 21;
  carry4 = s4 >> 21;
  s5 += carry4;
  s4 -= carry4 << 21;
  carry5 = s5 >> 21;
  s6 += carry5;
  s5 -= carry5 << 21;
  carry6 = s6 >> 21;
  s7 += carry6;
  s6 -= carry6 << 21;
  carry7 = s7 >> 21;
  s8 += carry7;
  s7 -= carry7 << 21;
  carry8 = s8 >> 21;
  s9 += carry8;
  s8 -= carry8 << 21;
  carry9 = s9 >> 21;
  s10 += carry9;
  s9 -= carry9 << 21;
  carry10 = s10 >> 21;
  s11 += carry10;
  s10 -= carry10 << 21;

  s[0] = (s0 >> 0) as u8;
  s[1] = (s0 >> 8) as u8;
  s[2] = ((s0 >> 16) | (s1 << 5)) as u8;
  s[3] = (s1 >> 3) as u8;
  s[4] = (s1 >> 11) as u8;
  s[5] = ((s1 >> 19) | (s2 << 2)) as u8;
  s[6] = (s2 >> 6) as u8;
  s[7] = ((s2 >> 14) | (s3 << 7)) as u8;
  s[8] = (s3 >> 1) as u8;
  s[9] = (s3 >> 9) as u8;
  s[10] = ((s3 >> 17) | (s4 << 4)) as u8;
  s[11] = (s4 >> 4) as u8;
  s[12] = (s4 >> 12) as u8;
  s[13] = ((s4 >> 20) | (s5 << 1)) as u8;
  s[14] = (s5 >> 7) as u8;
  s[15] = ((s5 >> 15) | (s6 << 6)) as u8;
  s[16] = (s6 >> 2) as u8;
  s[17] = (s6 >> 10) as u8;
  s[18] = ((s6 >> 18) | (s7 << 3)) as u8;
  s[19] = (s7 >> 5) as u8;
  s[20] = (s7 >> 13) as u8;
  s[21] = (s8 >> 0) as u8;
  s[22] = (s8 >> 8) as u8;
  s[23] = ((s8 >> 16) | (s9 << 5)) as u8;
  s[24] = (s9 >> 3) as u8;
  s[25] = (s9 >> 11) as u8;
  s[26] = ((s9 >> 19) | (s10 << 2)) as u8;
  s[27] = (s10 >> 6) as u8;
  s[28] = ((s10 >> 14) | (s11 << 7)) as u8;
  s[29] = (s11 >> 1) as u8;
  s[30] = (s11 >> 9) as u8;
  s[31] = (s11 >> 17) as u8;
}

#[cfg(test)]
#[test]
fn reduce() {
    let fname = "testdata/ed25519/reduce.test";
    run_test(fname.to_string(), 2, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negb, bbytes) = case.get("b").unwrap();

        assert!(!nega && !negb);
        assert_eq!(abytes.len(), 64);
        assert_eq!(bbytes.len(), 32);
        let mut copy = abytes.clone();
        x25519_sc_reduce(&mut copy);
        assert_eq!(&copy[0..32], &bbytes[0..]);
    });
}

/* Input:
 *   a[0]+256*a[1]+...+256^31*a[31] = a
 *   b[0]+256*b[1]+...+256^31*b[31] = b
 *   c[0]+256*c[1]+...+256^31*c[31] = c
 *
 * Output:
 *   s[0]+256*s[1]+...+256^31*s[31] = (ab+c) mod l
 *   where l = 2^252 + 27742317777372353535851937790883648493. */
pub fn x25519_sc_muladd(s: &mut [u8], a: &[u8], b: &[u8], c: &[u8])
{
  let a0  : i64 = 2097151 & load3(a) as i64;
  let a1  : i64 = 2097151 & (load4(&a[2..]) >> 5) as i64;
  let a2  : i64 = 2097151 & (load3(&a[5..]) >> 2) as i64;
  let a3  : i64 = 2097151 & (load4(&a[7..]) >> 7) as i64;
  let a4  : i64 = 2097151 & (load4(&a[10..]) >> 4) as i64;
  let a5  : i64 = 2097151 & (load3(&a[13..]) >> 1) as i64;
  let a6  : i64 = 2097151 & (load4(&a[15..]) >> 6) as i64;
  let a7  : i64 = 2097151 & (load3(&a[18..]) >> 3) as i64;
  let a8  : i64 = 2097151 &  load3(&a[21..]) as i64;
  let a9  : i64 = 2097151 & (load4(&a[23..]) >> 5) as i64;
  let a10 : i64 = 2097151 & (load3(&a[26..]) >> 2) as i64;
  let a11 : i64 =           (load4(&a[28..]) >> 7) as i64;
  let b0  : i64 = 2097151 &  load3(b) as i64;
  let b1  : i64 = 2097151 & (load4(&b[2..]) >> 5) as i64;
  let b2  : i64 = 2097151 & (load3(&b[5..]) >> 2) as i64;
  let b3  : i64 = 2097151 & (load4(&b[7..]) >> 7) as i64;
  let b4  : i64 = 2097151 & (load4(&b[10..]) >> 4) as i64;
  let b5  : i64 = 2097151 & (load3(&b[13..]) >> 1) as i64;
  let b6  : i64 = 2097151 & (load4(&b[15..]) >> 6) as i64;
  let b7  : i64 = 2097151 & (load3(&b[18..]) >> 3) as i64;
  let b8  : i64 = 2097151 &  load3(&b[21..]) as i64;
  let b9  : i64 = 2097151 & (load4(&b[23..]) >> 5) as i64;
  let b10 : i64 = 2097151 & (load3(&b[26..]) >> 2) as i64;
  let b11 : i64 =           (load4(&b[28..]) >> 7) as i64;
  let c0  : i64 = 2097151 &  load3(c) as i64;
  let c1  : i64 = 2097151 & (load4(&c[2..]) >> 5) as i64;
  let c2  : i64 = 2097151 & (load3(&c[5..]) >> 2) as i64;
  let c3  : i64 = 2097151 & (load4(&c[7..]) >> 7) as i64;
  let c4  : i64 = 2097151 & (load4(&c[10..]) >> 4) as i64;
  let c5  : i64 = 2097151 & (load3(&c[13..]) >> 1) as i64;
  let c6  : i64 = 2097151 & (load4(&c[15..]) >> 6) as i64;
  let c7  : i64 = 2097151 & (load3(&c[18..]) >> 3) as i64;
  let c8  : i64 = 2097151 &  load3(&c[21..]) as i64;
  let c9  : i64 = 2097151 & (load4(&c[23..]) >> 5) as i64;
  let c10 : i64 = 2097151 & (load3(&c[26..]) >> 2) as i64;
  let c11 : i64 =           (load4(&c[28..]) >> 7) as i64;
  let mut s0 : i64;
  let mut s1 : i64;
  let mut s2 : i64;
  let mut s3 : i64;
  let mut s4 : i64;
  let mut s5 : i64;
  let mut s6 : i64;
  let mut s7 : i64;
  let mut s8 : i64;
  let mut s9 : i64;
  let mut s10 : i64;
  let mut s11 : i64;
  let mut s12 : i64;
  let mut s13 : i64;
  let mut s14 : i64;
  let mut s15 : i64;
  let mut s16 : i64;
  let mut s17 : i64;
  let mut s18 : i64;
  let mut s19 : i64;
  let mut s20 : i64;
  let mut s21 : i64;
  let mut s22 : i64;
  let mut s23 : i64;
  let mut carry0 : i64;
  let mut carry1 : i64;
  let mut carry2 : i64;
  let mut carry3 : i64;
  let mut carry4 : i64;
  let mut carry5 : i64;
  let mut carry6 : i64;
  let mut carry7 : i64;
  let mut carry8 : i64;
  let mut carry9 : i64;
  let mut carry10 : i64;
  let mut carry11 : i64;
  let mut carry12 : i64;
  let mut carry13 : i64;
  let mut carry14 : i64;
  let mut carry15 : i64;
  let mut carry16 : i64;
  let     carry17 : i64;
  let     carry18 : i64;
  let     carry19 : i64;
  let     carry20 : i64;
  let     carry21 : i64;
  let     carry22 : i64;

  s0 = c0 + a0 * b0;
  s1 = c1 + a0 * b1 + a1 * b0;
  s2 = c2 + a0 * b2 + a1 * b1 + a2 * b0;
  s3 = c3 + a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
  s4 = c4 + a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;
  s5 = c5 + a0 * b5 + a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1 + a5 * b0;
  s6 = c6 + a0 * b6 + a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1 + a6 * b0;
  s7 = c7 + a0 * b7 + a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 +
       a6 * b1 + a7 * b0;
  s8 = c8 + a0 * b8 + a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 +
       a6 * b2 + a7 * b1 + a8 * b0;
  s9 = c9 + a0 * b9 + a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 +
       a6 * b3 + a7 * b2 + a8 * b1 + a9 * b0;
  s10 = c10 + a0 * b10 + a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 +
        a6 * b4 + a7 * b3 + a8 * b2 + a9 * b1 + a10 * b0;
  s11 = c11 + a0 * b11 + a1 * b10 + a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 +
        a6 * b5 + a7 * b4 + a8 * b3 + a9 * b2 + a10 * b1 + a11 * b0;
  s12 = a1 * b11 + a2 * b10 + a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5 +
        a8 * b4 + a9 * b3 + a10 * b2 + a11 * b1;
  s13 = a2 * b11 + a3 * b10 + a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6 + a8 * b5 +
        a9 * b4 + a10 * b3 + a11 * b2;
  s14 = a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7 + a8 * b6 + a9 * b5 +
        a10 * b4 + a11 * b3;
  s15 = a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7 + a9 * b6 + a10 * b5 +
        a11 * b4;
  s16 = a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7 + a10 * b6 + a11 * b5;
  s17 = a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7 + a11 * b6;
  s18 = a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7;
  s19 = a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8;
  s20 = a9 * b11 + a10 * b10 + a11 * b9;
  s21 = a10 * b11 + a11 * b10;
  s22 = a11 * b11;
  s23 = 0;

  carry0 = (s0 + (1 << 20)) >> 21;
  s1 += carry0;
  s0 -= carry0 << 21;
  carry2 = (s2 + (1 << 20)) >> 21;
  s3 += carry2;
  s2 -= carry2 << 21;
  carry4 = (s4 + (1 << 20)) >> 21;
  s5 += carry4;
  s4 -= carry4 << 21;
  carry6 = (s6 + (1 << 20)) >> 21;
  s7 += carry6;
  s6 -= carry6 << 21;
  carry8 = (s8 + (1 << 20)) >> 21;
  s9 += carry8;
  s8 -= carry8 << 21;
  carry10 = (s10 + (1 << 20)) >> 21;
  s11 += carry10;
  s10 -= carry10 << 21;
  carry12 = (s12 + (1 << 20)) >> 21;
  s13 += carry12;
  s12 -= carry12 << 21;
  carry14 = (s14 + (1 << 20)) >> 21;
  s15 += carry14;
  s14 -= carry14 << 21;
  carry16 = (s16 + (1 << 20)) >> 21;
  s17 += carry16;
  s16 -= carry16 << 21;
  carry18 = (s18 + (1 << 20)) >> 21;
  s19 += carry18;
  s18 -= carry18 << 21;
  carry20 = (s20 + (1 << 20)) >> 21;
  s21 += carry20;
  s20 -= carry20 << 21;
  carry22 = (s22 + (1 << 20)) >> 21;
  s23 += carry22;
  s22 -= carry22 << 21;

  carry1 = (s1 + (1 << 20)) >> 21;
  s2 += carry1;
  s1 -= carry1 << 21;
  carry3 = (s3 + (1 << 20)) >> 21;
  s4 += carry3;
  s3 -= carry3 << 21;
  carry5 = (s5 + (1 << 20)) >> 21;
  s6 += carry5;
  s5 -= carry5 << 21;
  carry7 = (s7 + (1 << 20)) >> 21;
  s8 += carry7;
  s7 -= carry7 << 21;
  carry9 = (s9 + (1 << 20)) >> 21;
  s10 += carry9;
  s9 -= carry9 << 21;
  carry11 = (s11 + (1 << 20)) >> 21;
  s12 += carry11;
  s11 -= carry11 << 21;
  carry13 = (s13 + (1 << 20)) >> 21;
  s14 += carry13;
  s13 -= carry13 << 21;
  carry15 = (s15 + (1 << 20)) >> 21;
  s16 += carry15;
  s15 -= carry15 << 21;
  carry17 = (s17 + (1 << 20)) >> 21;
  s18 += carry17;
  s17 -= carry17 << 21;
  carry19 = (s19 + (1 << 20)) >> 21;
  s20 += carry19;
  s19 -= carry19 << 21;
  carry21 = (s21 + (1 << 20)) >> 21;
  s22 += carry21;
  s21 -= carry21 << 21;

  s11 += s23 * 666643;
  s12 += s23 * 470296;
  s13 += s23 * 654183;
  s14 -= s23 * 997805;
  s15 += s23 * 136657;
  s16 -= s23 * 683901;
  //s23 = 0;

  s10 += s22 * 666643;
  s11 += s22 * 470296;
  s12 += s22 * 654183;
  s13 -= s22 * 997805;
  s14 += s22 * 136657;
  s15 -= s22 * 683901;
  //s22 = 0;

  s9 += s21 * 666643;
  s10 += s21 * 470296;
  s11 += s21 * 654183;
  s12 -= s21 * 997805;
  s13 += s21 * 136657;
  s14 -= s21 * 683901;
  //s21 = 0;

  s8 += s20 * 666643;
  s9 += s20 * 470296;
  s10 += s20 * 654183;
  s11 -= s20 * 997805;
  s12 += s20 * 136657;
  s13 -= s20 * 683901;
  //s20 = 0;

  s7 += s19 * 666643;
  s8 += s19 * 470296;
  s9 += s19 * 654183;
  s10 -= s19 * 997805;
  s11 += s19 * 136657;
  s12 -= s19 * 683901;
  //s19 = 0;

  s6 += s18 * 666643;
  s7 += s18 * 470296;
  s8 += s18 * 654183;
  s9 -= s18 * 997805;
  s10 += s18 * 136657;
  s11 -= s18 * 683901;
  //s18 = 0;

  carry6 = (s6 + (1 << 20)) >> 21;
  s7 += carry6;
  s6 -= carry6 << 21;
  carry8 = (s8 + (1 << 20)) >> 21;
  s9 += carry8;
  s8 -= carry8 << 21;
  carry10 = (s10 + (1 << 20)) >> 21;
  s11 += carry10;
  s10 -= carry10 << 21;
  carry12 = (s12 + (1 << 20)) >> 21;
  s13 += carry12;
  s12 -= carry12 << 21;
  carry14 = (s14 + (1 << 20)) >> 21;
  s15 += carry14;
  s14 -= carry14 << 21;
  carry16 = (s16 + (1 << 20)) >> 21;
  s17 += carry16;
  s16 -= carry16 << 21;

  carry7 = (s7 + (1 << 20)) >> 21;
  s8 += carry7;
  s7 -= carry7 << 21;
  carry9 = (s9 + (1 << 20)) >> 21;
  s10 += carry9;
  s9 -= carry9 << 21;
  carry11 = (s11 + (1 << 20)) >> 21;
  s12 += carry11;
  s11 -= carry11 << 21;
  carry13 = (s13 + (1 << 20)) >> 21;
  s14 += carry13;
  s13 -= carry13 << 21;
  carry15 = (s15 + (1 << 20)) >> 21;
  s16 += carry15;
  s15 -= carry15 << 21;

  s5 += s17 * 666643;
  s6 += s17 * 470296;
  s7 += s17 * 654183;
  s8 -= s17 * 997805;
  s9 += s17 * 136657;
  s10 -= s17 * 683901;
  //s17 = 0;

  s4 += s16 * 666643;
  s5 += s16 * 470296;
  s6 += s16 * 654183;
  s7 -= s16 * 997805;
  s8 += s16 * 136657;
  s9 -= s16 * 683901;
  //s16 = 0;

  s3 += s15 * 666643;
  s4 += s15 * 470296;
  s5 += s15 * 654183;
  s6 -= s15 * 997805;
  s7 += s15 * 136657;
  s8 -= s15 * 683901;
  //s15 = 0;

  s2 += s14 * 666643;
  s3 += s14 * 470296;
  s4 += s14 * 654183;
  s5 -= s14 * 997805;
  s6 += s14 * 136657;
  s7 -= s14 * 683901;
  //s14 = 0;

  s1 += s13 * 666643;
  s2 += s13 * 470296;
  s3 += s13 * 654183;
  s4 -= s13 * 997805;
  s5 += s13 * 136657;
  s6 -= s13 * 683901;
  //s13 = 0;

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = (s0 + (1 << 20)) >> 21;
  s1 += carry0;
  s0 -= carry0 << 21;
  carry2 = (s2 + (1 << 20)) >> 21;
  s3 += carry2;
  s2 -= carry2 << 21;
  carry4 = (s4 + (1 << 20)) >> 21;
  s5 += carry4;
  s4 -= carry4 << 21;
  carry6 = (s6 + (1 << 20)) >> 21;
  s7 += carry6;
  s6 -= carry6 << 21;
  carry8 = (s8 + (1 << 20)) >> 21;
  s9 += carry8;
  s8 -= carry8 << 21;
  carry10 = (s10 + (1 << 20)) >> 21;
  s11 += carry10;
  s10 -= carry10 << 21;

  carry1 = (s1 + (1 << 20)) >> 21;
  s2 += carry1;
  s1 -= carry1 << 21;
  carry3 = (s3 + (1 << 20)) >> 21;
  s4 += carry3;
  s3 -= carry3 << 21;
  carry5 = (s5 + (1 << 20)) >> 21;
  s6 += carry5;
  s5 -= carry5 << 21;
  carry7 = (s7 + (1 << 20)) >> 21;
  s8 += carry7;
  s7 -= carry7 << 21;
  carry9 = (s9 + (1 << 20)) >> 21;
  s10 += carry9;
  s9 -= carry9 << 21;
  carry11 = (s11 + (1 << 20)) >> 21;
  s12 += carry11;
  s11 -= carry11 << 21;

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = s0 >> 21;
  s1 += carry0;
  s0 -= carry0 << 21;
  carry1 = s1 >> 21;
  s2 += carry1;
  s1 -= carry1 << 21;
  carry2 = s2 >> 21;
  s3 += carry2;
  s2 -= carry2 << 21;
  carry3 = s3 >> 21;
  s4 += carry3;
  s3 -= carry3 << 21;
  carry4 = s4 >> 21;
  s5 += carry4;
  s4 -= carry4 << 21;
  carry5 = s5 >> 21;
  s6 += carry5;
  s5 -= carry5 << 21;
  carry6 = s6 >> 21;
  s7 += carry6;
  s6 -= carry6 << 21;
  carry7 = s7 >> 21;
  s8 += carry7;
  s7 -= carry7 << 21;
  carry8 = s8 >> 21;
  s9 += carry8;
  s8 -= carry8 << 21;
  carry9 = s9 >> 21;
  s10 += carry9;
  s9 -= carry9 << 21;
  carry10 = s10 >> 21;
  s11 += carry10;
  s10 -= carry10 << 21;
  carry11 = s11 >> 21;
  s12 += carry11;
  s11 -= carry11 << 21;

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  //s12 = 0;

  carry0 = s0 >> 21;
  s1 += carry0;
  s0 -= carry0 << 21;
  carry1 = s1 >> 21;
  s2 += carry1;
  s1 -= carry1 << 21;
  carry2 = s2 >> 21;
  s3 += carry2;
  s2 -= carry2 << 21;
  carry3 = s3 >> 21;
  s4 += carry3;
  s3 -= carry3 << 21;
  carry4 = s4 >> 21;
  s5 += carry4;
  s4 -= carry4 << 21;
  carry5 = s5 >> 21;
  s6 += carry5;
  s5 -= carry5 << 21;
  carry6 = s6 >> 21;
  s7 += carry6;
  s6 -= carry6 << 21;
  carry7 = s7 >> 21;
  s8 += carry7;
  s7 -= carry7 << 21;
  carry8 = s8 >> 21;
  s9 += carry8;
  s8 -= carry8 << 21;
  carry9 = s9 >> 21;
  s10 += carry9;
  s9 -= carry9 << 21;
  carry10 = s10 >> 21;
  s11 += carry10;
  s10 -= carry10 << 21;

  s[0] = (s0 >> 0) as u8;
  s[1] = (s0 >> 8) as u8;
  s[2] = ((s0 >> 16) | (s1 << 5)) as u8;
  s[3] = (s1 >> 3) as u8;
  s[4] = (s1 >> 11) as u8;
  s[5] = ((s1 >> 19) | (s2 << 2)) as u8;
  s[6] = (s2 >> 6) as u8;
  s[7] = ((s2 >> 14) | (s3 << 7)) as u8;
  s[8] = (s3 >> 1) as u8;
  s[9] = (s3 >> 9) as u8;
  s[10] = ((s3 >> 17) | (s4 << 4)) as u8;
  s[11] = (s4 >> 4) as u8;
  s[12] = (s4 >> 12) as u8;
  s[13] = ((s4 >> 20) | (s5 << 1)) as u8;
  s[14] = (s5 >> 7) as u8;
  s[15] = ((s5 >> 15) | (s6 << 6)) as u8;
  s[16] = (s6 >> 2) as u8;
  s[17] = (s6 >> 10) as u8;
  s[18] = ((s6 >> 18) | (s7 << 3)) as u8;
  s[19] = (s7 >> 5) as u8;
  s[20] = (s7 >> 13) as u8;
  s[21] = (s8 >> 0) as u8;
  s[22] = (s8 >> 8) as u8;
  s[23] = ((s8 >> 16) | (s9 << 5)) as u8;
  s[24] = (s9 >> 3) as u8;
  s[25] = (s9 >> 11) as u8;
  s[26] = ((s9 >> 19) | (s10 << 2)) as u8;
  s[27] = (s10 >> 6) as u8;
  s[28] = ((s10 >> 14) | (s11 << 7)) as u8;
  s[29] = (s11 >> 1) as u8;
  s[30] = (s11 >> 9) as u8;
  s[31] = (s11 >> 17) as u8;
}

#[cfg(test)]
#[test]
fn muladd() {
    let fname = "testdata/ed25519/muladd.test";
    run_test(fname.to_string(), 4, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negb, bbytes) = case.get("b").unwrap();
        let (negc, cbytes) = case.get("c").unwrap();
        let (negd, dbytes) = case.get("d").unwrap();

        assert!(!nega && !negb && !negc && !negd);
        let mut mine = [0; 32];
        x25519_sc_muladd(&mut mine, abytes, bbytes, cbytes);
        for i in 0..32 {
          assert_eq!(&mine[i], &dbytes[i]);
        }
    });
}

pub fn curve25519_scalar_mask(a: &mut [u8])
{
  assert_eq!(a.len(), 32);
  a[0] &= 248;
  a[31] &= 127;
  a[31] |= 64;
}

/* Replace (f,g) with (g,f) if b == 1;
 * replace (f,g) with (f,g) if b == 0.
 *
 * Preconditions: b in {0,1}. */
//fn fe_cswap(f: &mut FieldElement, g: &mut FieldElement, inb: bool) {
//  let b = if inb { 0xFFFFFFFFu32 as i32 } else { 0x00000000 };
//  for i in 0..NUM_ELEMENT_LIMBS {
//    let mut x = f[i] ^ g[i];
//    x &= b;
//    f[i] ^= x;
//    g[i] ^= x;
//  }
//}

/* h = f * 121666
 * Can overlap h with f.
 *
 * Preconditions:
 *    |f| bounded by 1.1*2^26,1.1*2^25,1.1*2^26,1.1*2^25,etc.
 *
 * Postconditions:
 *    |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc. */
//fn fe_mul121666(h: &mut FieldElement, f: &FieldElement)
//{
//  let f0 = f[0];
//  let f1 = f[1];
//  let f2 = f[2];
//  let f3 = f[3];
//  let f4 = f[4];
//  let f5 = f[5];
//  let f6 = f[6];
//  let f7 = f[7];
//  let f8 = f[8];
//  let f9 = f[9];
//  let mut h0 = (f0 as i64) * 121666;
//  let mut h1 = (f1 as i64) * 121666;
//  let mut h2 = (f2 as i64) * 121666;
//  let mut h3 = (f3 as i64) * 121666;
//  let mut h4 = (f4 as i64) * 121666;
//  let mut h5 = (f5 as i64) * 121666;
//  let mut h6 = (f6 as i64) * 121666;
//  let mut h7 = (f7 as i64) * 121666;
//  let mut h8 = (f8 as i64) * 121666;
//  let mut h9 = (f9 as i64) * 121666;
//
//  let carry9 = h9 + (1 << 24); h0 += (carry9 >> 25) * 19; h9 -= carry9 & KTOP_39BITS;
//  let carry1 = h1 + (1 << 24); h2 += carry1 >> 25; h1 -= carry1 & KTOP_39BITS;
//  let carry3 = h3 + (1 << 24); h4 += carry3 >> 25; h3 -= carry3 & KTOP_39BITS;
//  let carry5 = h5 + (1 << 24); h6 += carry5 >> 25; h5 -= carry5 & KTOP_39BITS;
//  let carry7 = h7 + (1 << 24); h8 += carry7 >> 25; h7 -= carry7 & KTOP_39BITS;
//
//  let carry0 = h0 + (1 << 25); h1 += carry0 >> 26; h0 -= carry0 & KTOP_38BITS;
//  let carry2 = h2 + (1 << 25); h3 += carry2 >> 26; h2 -= carry2 & KTOP_38BITS;
//  let carry4 = h4 + (1 << 25); h5 += carry4 >> 26; h4 -= carry4 & KTOP_38BITS;
//  let carry6 = h6 + (1 << 25); h7 += carry6 >> 26; h6 -= carry6 & KTOP_38BITS;
//  let carry8 = h8 + (1 << 25); h9 += carry8 >> 26; h8 -= carry8 & KTOP_38BITS;
//
//  h[0] = h0 as i32;
//  h[1] = h1 as i32;
//  h[2] = h2 as i32;
//  h[3] = h3 as i32;
//  h[4] = h4 as i32;
//  h[5] = h5 as i32;
//  h[6] = h6 as i32;
//  h[7] = h7 as i32;
//  h[8] = h8 as i32;
//  h[9] = h9 as i32;
//}

//fn x25519_scalar_mult(out: &mut [u8], scalar: &[u8], point: &[u8])
//{
//  assert_eq!(out.len(), 32);
//  assert_eq!(scalar.len(), 32);
//  assert_eq!(point.len(), 32);
//
//  let mut x1   = FieldElement::new();
//  let mut x2   = FieldElement::new();
//  let mut z2   = FieldElement::new();
//  let mut x3   = FieldElement::new();
//  let mut z3   = FieldElement::new();
//  let mut tmp0 = FieldElement::new();
//  let mut tmp1 = FieldElement::new();
//  let mut tmp2;
//  let mut e    = [0; 32];
//
//  e.copy_from_slice(scalar); 
//  curve25519_scalar_mask(&mut e);
//  fe_frombytes(&mut x1, &point);
//  fe1(&mut x2);
//  fe0(&mut z2);
//  x3.copy_from_slice(&x1);
//  fe1(&mut z3);
//
//  let mut swap = 0;
//  let mut pos = 254;
//  loop {
//    let b = 1 & (e[pos / 8] >> (pos & 7));
//    swap ^= b;
//    fe_cswap(&mut x2, &mut x3, swap != 0);
//    fe_cswap(&mut z2, &mut z3, swap != 0);
//    swap = b;
//    fe_sub(&mut tmp0, &x3, &z3);
//    fe_sub(&mut tmp1, &x2, &z2);
//    tmp2 = x2.clone();
//    fe_add(&mut x2,   &tmp2, &z2);
//    fe_add(&mut z2,   &x3, &z3);
//    fe_mul(&mut z3,   &tmp0, &x2);
//    tmp2 = z2.clone();
//    fe_mul(&mut z2,   &tmp2, &tmp1);
//    fe_square(&mut tmp0, &tmp1);
//    fe_square(&mut tmp1, &x2);
//    fe_add(&mut x3,   &z3, &z2);
//    tmp2 = z2.clone();
//    fe_sub(&mut z2,   &z3, &tmp2);
//    fe_mul(&mut x2,   &tmp1, &tmp0);
//    tmp2 = tmp1.clone();
//    fe_sub(&mut tmp1, &tmp2, &tmp0);
//    tmp2 = z2.clone();
//    fe_square(&mut z2,   &tmp2);
//    fe_mul121666(&mut z3, &tmp1);
//    tmp2 = x3.clone();
//    fe_square( &mut x3,   &tmp2);
//    tmp2 = tmp0.clone();
//    fe_add(&mut tmp0, &tmp2, &z3);
//    fe_mul(&mut z3,   &x1,   &z2);
//    fe_mul(&mut z2,   &tmp1, &tmp0);
//    if pos == 0 {
//      break;
//    } else {
//      pos -= 1;
//    }
//  }
//  fe_cswap(&mut x2, &mut x3, swap != 0);
//  fe_cswap(&mut z2, &mut z3, swap != 0);
//
//  z2 = fe_invert(&z2);
//  tmp2 = x2.clone();
//  fe_mul(&mut x2, &tmp2, &z2);
//  fe_tobytes(out, &x2);
//}

pub fn x25519_public_from_private(public: &mut [u8], private: &[u8])
{
  assert_eq!(private.len(), 32);
  assert_eq!(public.len(), 32);

  let mut e = [0; 32];
  e.copy_from_slice(private);
  curve25519_scalar_mask(&mut e);

  #[allow(non_snake_case)]
  let mut A = Point::new();
  x25519_ge_scalarmult_base(&mut A, &e);

  /* We only need the u-coordinate of the curve25519 point. The map is
   * u=(y+1)/(1-y). Since y=Y/Z, this gives u=(Z+Y)/(Z-Y). */
  let mut zplusy = FieldElement::new();
  let mut zminusy = FieldElement::new();
  fe_add(&mut zplusy,  &A.z, &A.y);
  fe_sub(&mut zminusy, &A.z, &A.y);
  let zminusy_inv = fe_invert(&zminusy);
  let copy = zplusy.clone();
  fe_mul(&mut zplusy, &copy, &zminusy_inv);
  fe_tobytes(public, &zplusy);
}

#[cfg(test)]
#[test]
fn public_from_private() {
    let fname = "testdata/ed25519/pubfrompriv.test";
    run_test(fname.to_string(), 2, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negb, bbytes) = case.get("b").unwrap();

        assert!(!nega && !negb);
        let mut mine = [0; 32];
        x25519_public_from_private(&mut mine, abytes);
        for i in 0..32 {
          assert_eq!(mine[i], bbytes[i]);
        }
    });
}

fn into_encoded_point(bytes: &mut [u8], x: &FieldElement, y: &FieldElement, z: &FieldElement)
{
    let mut x_over_z = FieldElement::new();
    let mut y_over_z = FieldElement::new();
    assert!(bytes.len() >= 32);

    let recip = fe_invert(z);
    fe_mul(&mut x_over_z, x, &recip);
    fe_mul(&mut y_over_z, y, &recip);
    fe_tobytes(bytes, &y_over_z);
    let sign_bit = if fe_isnegative(&x_over_z) { 1 } else { 0 };

    // The preceding computations must execute in constant time, but this
    // doesn't need to.
    bytes[31] ^= sign_bit << 7;
}
