// Luhn algorithm for credit card number validation
export function luhnCheck(digits: string): boolean {
  const nums = digits.replace(/\D/g, '');
  if (nums.length < 13) return false;
  let sum = 0;
  let isOdd = true;
  for (let i = nums.length - 1; i >= 0; i--) {
    let digit = parseInt(nums[i] ?? '0', 10);
    if (!isOdd) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    isOdd = !isOdd;
  }
  return sum % 10 === 0;
}
