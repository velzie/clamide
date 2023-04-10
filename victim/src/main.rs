use std::hint::black_box;

fn main() {
    println!("Hello, world!");
    black_box(heapalloc());
    std::thread::park();
}
fn heapalloc() {
    let heaping_string = Box::leak(Box::new(String::from(
        String::from("STRING_PART") + "YYY_OTGER_PART",
    )));
    dbg!(heaping_string);

    let other = String::from(String::from("SOX_PART") + "YYY_SOX_PART");
    dbg!(other);

    let stacking_string = "COC_STACKED_STR";
    dbg!(stacking_string);

    loop {}
}
