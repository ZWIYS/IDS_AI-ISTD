test_that("safe_num handles edge cases", {
  expect_equal(safe_num(NA), 0)
  expect_equal(safe_num(Inf), 0)
  expect_equal(safe_num("3.14"), 3.14)
})

test_that("safe_max handles edge cases", {
  expect_equal(safe_max(integer(0)), 0)
  expect_equal(safe_max(c(NA, NA)), 0)
  expect_equal(safe_max(c(1, NA, 5, Inf)), 5)
  expect_type(safe_max(integer(0)), "double")
})

test_that("shannon_entropy", {
  expect_equal(shannon_entropy(""), 0)
  expect_equal(shannon_entropy("aaaa"), 0)
  expect_equal(shannon_entropy("ab"), 1)
})
