org 0xe9e0

def check_even_odd(n) {
  if n%2==0{
    return 0x1      # Even
  } else {
    return 0x0      # Odd
  }
}

py.check_even_odd(0x2)
py.check_even_odd(0x3)