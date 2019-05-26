#[cfg(test)]
use testing::run_test;

use ed25519::fe::*;
use ed25519::constants::*;
use std::ops::*;

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
pub struct PointP1P1 {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    t: FieldElement
}

impl PointP1P1 {
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

impl<'a,'b> Add<&'a Precomp> for &'b Point
{
    type Output = PointP1P1;

    fn add(self, q: &Precomp) -> PointP1P1
    {
        let mut rx;
        let mut ry;
        let mut rz;
        let mut rt;

        rx = &self.y + &self.x;
        ry = &self.y - &self.x;
        rz = &rx * &q.yplusx;
        ry *= &q.yminusx;
        rt = &q.xy2d * &self.t;
        let t0 = &self.z + &self.z;
        rx = &rz - &ry;
        ry += &rz;
        rz = &t0 + &rt;
        rt = &t0 - &rt;

        PointP1P1 { x: rx, y: ry, z: rz, t: rt }
    }
}

impl<'a,'b> Sub<&'a Precomp> for &'b Point
{
    type Output = PointP1P1;

    /* r = p - q */
    fn sub(self, q: &Precomp) -> PointP1P1
    {
        let mut rx = &self.y + &self.x;
        let mut ry = &self.y - &self.x;
        let mut rz = &rx * &q.yminusx;
        ry *= &q.yplusx;
        let mut rt = &q.xy2d * &self.t;
        let t0 = &self.z + &self.z;
        rx = &rz - &ry;
        ry += &rz;
        rz = &t0 - &rt;
        rt += &t0;
        PointP1P1{ x: rx, y: ry, z: rz, t: rt }
    }
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

        let myb = &a + &c;
        assert_eq!(myb, b);
        let myd = &a - &c;
        assert_eq!(myd, d);
    });
}

impl<'a,'b> Add<&'a Cached> for &'b Point
{
    type Output = PointP1P1;

    fn add(self, q: &Cached) -> PointP1P1
    {
        let mut rx;
        let mut ry;
        let mut rz;
        let mut rt;

        rx = &self.y + &self.x;
        ry = &self.y - &self.x;
        rz = &rx * &q.yplusx;
        ry *= &q.yminusx;
        rt = &q.t2d * &self.t;
        rx = &self.z * &q.z;
        let t0 = &rx + &rx;
        rx = &rz - &ry;
        ry += &rz;
        rz = &t0 + &rt;
        rt = &t0 - &rt;

        PointP1P1{ x: rx, y: ry, z: rz, t: rt }
    }
}

impl<'a,'b> Sub<&'a Cached> for &'b Point
{
    type Output = PointP1P1;

    fn sub(self, q: &Cached) -> PointP1P1
    {
        let mut rx;
        let mut ry;
        let mut rz;
        let mut rt;

        rx = &self.y + &self.x;
        ry = &self.y - &self.x;
        rz = &rx * &q.yminusx;
        ry *= &q.yplusx;
        rt = &q.t2d * &self.t;
        rx = &self.z * &q.z;
        let t0 = &rx + &rx;
        rx = &rz - &ry;
        ry += &rz;
        rz = &t0 - &rt;
        rt += &t0;

        PointP1P1{ x: rx, y: ry, z: rz, t: rt }
    }
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

        let myb = &a + &c;
        assert_eq!(myb, b);
        let myd = &a - &c;
        assert_eq!(myd, d);
    });
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
  
      let mut r;
      let mut t;
  
      let mut h = Point::zero();
      for i in &[1,3,5,7,9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,47,49,51,53,55,57,59,61,63] {
          t = Precomp::table_select(*i / 2, e[*i as usize]);
          r = &h + &t;
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
          t = Precomp::table_select(*i / 2, e[*i as usize]);
          r = &h + &t;
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

impl Point2
{
    /* r = a * A + b * B
     * where a = a[0]+256*a[1]+...+256^31 a[31].
     * and b = b[0]+256*b[1]+...+256^31 b[31].
     * B is the Ed25519 base point (x,4/5) with x positive. */
    #[allow(non_snake_case)]
    pub fn double_scalarmult_vartime(a: &[u8], A: &Point, b: &[u8]) -> Point2
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
        t = &A2 + &Ai[0];
        let mut u = Point::from(&t);
        Ai[1] = Cached::from(&u);
        t = &A2 + &Ai[1];
        u = Point::from(&t);
        Ai[2] = Cached::from(&u);
        t = &A2 + &Ai[2];
        u = Point::from(&t);
        Ai[3] = Cached::from(&u);
        t = &A2 + &Ai[3];
        u = Point::from(&t);
        Ai[4] = Cached::from(&u);
        t = &A2 + &Ai[4];
        u = Point::from(&t);
        Ai[5] = Cached::from(&u);
        t = &A2 + &Ai[5];
        u = Point::from(&t);
        Ai[6] = Cached::from(&u);
        t = &A2 + &Ai[6];
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
                t = &u + &Ai[idx]
            } else if aslide[i as usize] < 0 {
                u = Point::from(&t);
                let idx = ((-aslide[i as usize]) / 2) as usize;
                t = &u - &Ai[idx];
            }
      
            if bslide[i as usize] > 0 {
                u = Point::from(&t);
                let idx = (bslide[i as usize] / 2) as usize;
                t = &u + &BI[idx];
            } else if bslide[i as usize] < 0 {
                u = Point::from(&t);
                let idx = ((-bslide[i as usize]) / 2) as usize;
                t = &u - &BI[idx];
            }
    
            r = Point2::from(&t); 
            i -= 1;
        }
    
        r
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
        let mine = Point2::double_scalarmult_vartime(&abytes, &b, &cbytes);
        assert_eq!(mine, d);
    });
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
