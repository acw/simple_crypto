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
    fn zero() -> Point
    {
        Point {
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::one(),
            t: FieldElement::zero(),
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
  
    /// Convert 32 bytes into an ED25519 point. This routine is not
    /// statically timed, so don't use it if that's important to you.
    pub fn from_bytes(s: &[u8]) -> Option<Point>
    {
        let hy = FieldElement::from_bytes(s);
        let hz = FieldElement::one();
        let mut u = hy.square();
        let mut v = &u * &D;
        u = &u - &hz; /* u = y^2-1 */
        v += &hz;
  
        let mut v3 = v.square();
        v3 *= &v; /* v3 = v^3 */
        let mut hx = v3.square();
        hx *= &v;
        hx *= &u; /* x = uv^7 */
        hx = hx.pow22523(); /* x = (uv^7)^((q-5)/8) */
        hx *= &v3;
        hx *= &u; /* x = uv^3(uv^7)^((q-5)/8) */
  
        let mut vxx = hx.square();
        vxx *= &v;
        let mut check = &vxx - &u; /* vx^2-u */
        if check.isnonzero() {
            check = &vxx + &u;
            if check.isnonzero() {
                return None;
            }
            hx *= &SQRTM1;
        }
  
        if hx.isnegative() != ((s[31] >> 7) == 1) {
            hx = -&hx;
        }
  
        let ht = &hx * &hy;
        return Some(Point{ x: hx, y: hy, z: hz, t: ht });
    }
  
    pub fn encode(&self) -> Vec<u8>
    {
        into_encoded_point(&self.x, &self.y, &self.z)
    }
  
    pub fn invert(&mut self)
    {
        self.x = -&self.x;
        self.t = -&self.t;
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

#[cfg(test)]
#[test]
fn from_bytes_vartime() {
    let fname = "testdata/ed25519/fbv.test";
    run_test(fname.to_string(), 3, |case| {
        let (nega, abytes) = case.get("a").unwrap();
        let (negb, bbytes) = case.get("b").unwrap();
        let (negc, cbytes) = case.get("c").unwrap();

        assert!(!nega && !negb && !negc);
        let target = Point::load_test_value(&cbytes);
        let mine = Point::from_bytes(&abytes);
        if bbytes.len() < cbytes.len() {
            assert!(mine.is_none());
        } else {
            assert_eq!(target, mine.unwrap());
        }
    });
}

#[derive(Debug,PartialEq)]
pub struct Point2 {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
}

impl Point2 {
    pub fn zero() -> Point2
    {
        Point2 {
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::one()  
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
  
    pub fn encode(&self) -> Vec<u8>
    {
        into_encoded_point(&self.x, &self.y, &self.z)
    }
}

impl<'a> From<&'a Point> for Point2 {
    fn from(p: &Point) -> Point2 {
        Point2 {
            x: p.x.clone(),
            y: p.y.clone(),
            z: p.z.clone(),
        }
    }
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

impl<'a> From<&'a Point> for Cached
{
    fn from(p: &Point) -> Cached
    {
        Cached {
            yplusx: &p.y + &p.x,
            yminusx: &p.y - &p.x,
            z: p.z.clone(),
            t2d: &p.t * &D2,
        }    
    }
}

impl<'a> From<&'a PointP1P1> for Point2
{
    fn from(p: &PointP1P1) -> Point2
    {
        Point2 {
            x: &p.x * &p.t,
            y: &p.y * &p.z,
            z: &p.z * &p.t,
        }
    }
}

impl<'a> From<&'a PointP1P1> for Point 
{
    fn from(p: &PointP1P1) -> Point
    {
        Point {
            x: &p.x * &p.t,
            y: &p.y * &p.z,
            z: &p.z * &p.t,
            t: &p.x * &p.y,
        }
    }
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

        let myc = Cached::from(&a);
        assert_eq!(myc, c);

        let myt = Point2::from(&a);
        assert_eq!(myt, t);

        let myo = a.double();
        assert_eq!(myo, o);

        let myd = Point2::from(&o);
        assert_eq!(myd, d);

        let myb = Point::from(&o);
        assert_eq!(myb, b);
    });
}

/* r = 2 * p */
impl Point2 {
    fn double(&self) -> PointP1P1
    {
        let x0 = self.x.square();
        let z0 = self.y.square();
        let t0 = self.z.sq2();
        let y0 = &self.x + &self.y;
        let ry = &z0 + &x0;
        let rz = &z0 - &x0;
        let rx = &y0.square() - &ry;
        let rt = &t0 - &rz;
        PointP1P1 { x: rx, y: ry, z: rz, t: rt }
    }
}

/* r = 2 * p */
impl Point {
    fn double(&self) -> PointP1P1
    {
        Point2::from(self).double()
    }
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

        let myb = a.double();
        assert_eq!(myb, b);
        let myd = c.double();
        assert_eq!(myd, d);
    });
}

/* r = p + q */
fn ge_madd(r: &mut PointP1P1, p: &Point, q: &Precomp)
{
    r.x = &p.y + &p.x;
    r.y = &p.y - &p.x;
    r.z = &r.x * &q.yplusx;
    r.y *= &q.yminusx;
    r.t = &q.xy2d * &p.t;
    let t0 = &p.z + &p.z;
    r.x = &r.z - &r.y;
    r.y += &r.z;
    r.z = &t0 + &r.t;
    r.t = &t0 - &r.t;
}

/* r = p - q */
fn ge_msub(r: &mut PointP1P1, p: &Point, q: &Precomp)
{
    r.x = &p.y + &p.x;
    r.y = &p.y - &p.x;
    r.z = &r.x * &q.yminusx;
    r.y *= &q.yplusx;
    r.t = &q.xy2d * &p.t;
    let t0 = &p.z + &p.z;
    r.x = &r.z - &r.y;
    r.y += &r.z;
    r.z = &t0 - &r.t;
    r.t += &t0;
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
    r.x = &p.y + &p.x;
    r.y = &p.y - &p.x;
    r.z = &r.x * &q.yplusx;
    r.y *= &q.yminusx;
    r.t = &q.t2d * &p.t;
    r.x = &p.z * &q.z;
    let t0 = &r.x + &r.x;
    r.x = &r.z - &r.y;
    r.y += &r.z;
    r.z = &t0 + &r.t;
    r.t = &t0 - &r.t;
}

/* r = p - q */
fn x25519_ge_sub(r: &mut PointP1P1, p: &Point, q: &Cached)
{
    r.x = &p.y + &p.x;
    r.y = &p.y - &p.x;
    r.z = &r.x * &q.yminusx;
    r.y *= &q.yplusx;
    r.t = &q.t2d * &p.t;
    r.x = &p.z * &q.z;
    let t0 = &r.x + &r.x;
    r.x = &r.z - &r.y;
    r.y += &r.z;
    r.z = &t0 - &r.t;
    r.t += &t0;
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

fn negative(b: i8) -> u8
{
    let mut x = b as u32;
    x >>= 31; /* 1: yes; 0: no */
    x as u8
}

fn table_select(pos: i32, b: i8) -> Precomp
{
    let mut minust = Precomp::new();
    let mut res = Precomp::zero();
    let bnegative = negative(b);
    let babs = b - (((-(bnegative as i8)) & b) << 1);
    
    res.cmov(&K25519_PRECOMP[pos as usize][0], equal(babs, 1));
    res.cmov(&K25519_PRECOMP[pos as usize][1], equal(babs, 2));
    res.cmov(&K25519_PRECOMP[pos as usize][2], equal(babs, 3));
    res.cmov(&K25519_PRECOMP[pos as usize][3], equal(babs, 4));
    res.cmov(&K25519_PRECOMP[pos as usize][4], equal(babs, 5));
    res.cmov(&K25519_PRECOMP[pos as usize][5], equal(babs, 6));
    res.cmov(&K25519_PRECOMP[pos as usize][6], equal(babs, 7));
    res.cmov(&K25519_PRECOMP[pos as usize][7], equal(babs, 8));
    minust.yplusx.overwrite_with(&res.yminusx);
    minust.yminusx.overwrite_with(&res.yplusx);
    minust.xy2d = -&res.xy2d;
    res.cmov(&minust, bnegative != 0);
    res
}

impl Point {
    /* h = a * B
     * where a = a[0]+256*a[1]+...+256^31 a[31]
     * B is the Ed25519 base point (x,4/5) with x positive.
     *
     * Preconditions:
     *   a[31] <= 127 */
    pub fn scalarmult_base(a: &[u8]) -> Point
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
      let mut t;
  
      let mut h = Point::zero();
      for i in &[1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,47,49,51,53,55,57,59,61,63] {
          t = table_select(*i / 2, e[*i as usize]);
          ge_madd(&mut r, &h, &t);
          h = Point::from(&r);
      }
  
      r = h.double();
      let mut s = Point2::from(&r);
      r = s.double();
      s = Point2::from(&r);
      r = s.double();
      s = Point2::from(&r);
      r = s.double();
      h = Point::from(&r);
  
      for i in &[0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38,40,42,44,46,48,50,52,54,56,58,60,62] {
          t = table_select(*i / 2, e[*i as usize]);
          ge_madd(&mut r, &h, &t);
          h = Point::from(&r);
      }

      h
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
        let b    = Point::load_test_value(bbytes);
        let mine = Point::scalarmult_base(&abytes);
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
pub fn ge_double_scalarmult_vartime(a: &[u8], A: &Point, b: &[u8]) -> Point2
{
    let mut aslide: [i8; 256] = [0; 256];
    let mut bslide: [i8; 256] = [0; 256];
    #[allow(non_snake_case)]
    let mut Ai: [Cached; 8] = [Cached::new(), Cached::new(), Cached::new(), Cached::new(),
                               Cached::new(), Cached::new(), Cached::new(), Cached::new()];
    #[allow(non_snake_case)]

    slide(&mut aslide, &a);
    slide(&mut bslide, &b);

    Ai[0] = Cached::from(A);
    let mut t = A.double();
    let A2 = Point::from(&t);
    x25519_ge_add(&mut t, &A2, &Ai[0]);
    let mut u = Point::from(&t);
    Ai[1] = Cached::from(&u);
    x25519_ge_add(&mut t, &A2, &Ai[1]);
    u = Point::from(&t);
    Ai[2] = Cached::from(&u);
    x25519_ge_add(&mut t, &A2, &Ai[2]);
    u = Point::from(&t);
    Ai[3] = Cached::from(&u);
    x25519_ge_add(&mut t, &A2, &Ai[3]);
    u = Point::from(&t);
    Ai[4] = Cached::from(&u);
    x25519_ge_add(&mut t, &A2, &Ai[4]);
    u = Point::from(&t);
    Ai[5] = Cached::from(&u);
    x25519_ge_add(&mut t, &A2, &Ai[5]);
    u = Point::from(&t);
    Ai[6] = Cached::from(&u);
    x25519_ge_add(&mut t, &A2, &Ai[6]);
    u = Point::from(&t);
    Ai[7] = Cached::from(&u);

    let mut r = Point2::zero();

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
        t = r.double();
  
        if aslide[i as usize] > 0 {
            u = Point::from(&t);
            let idx = (aslide[i as usize] / 2) as usize;
            x25519_ge_add(&mut t, &u, &Ai[idx]);
        } else if aslide[i as usize] < 0 {
            u = Point::from(&t);
            let idx = ((-aslide[i as usize]) / 2) as usize;
            x25519_ge_sub(&mut t, &u, &Ai[idx]);
        }
  
        if bslide[i as usize] > 0 {
            u = Point::from(&t);
            let idx = (bslide[i as usize] / 2) as usize;
            ge_madd(&mut t, &u, &BI[idx]);
        } else if bslide[i as usize] < 0 {
            u = Point::from(&t);
            let idx = ((-bslide[i as usize]) / 2) as usize;
            ge_msub(&mut t, &u, &BI[idx]);
        }

        r = Point2::from(&t); 
        i -= 1;
    }

    r
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
        let mine = ge_double_scalarmult_vartime(&abytes, &b, &cbytes);
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

fn into_encoded_point(x: &FieldElement, y: &FieldElement, z: &FieldElement) -> Vec<u8>
{
    let recip = z.invert();
    let x_over_z = x * &recip;
    let y_over_z = y * &recip;
    let mut bytes = y_over_z.to_bytes();
    let sign_bit = if x_over_z.isnegative() { 1 } else { 0 };
    // The preceding computations must execute in constant time, but this
    // doesn't need to.
    bytes[31] ^= sign_bit << 7;
    bytes
}
