// Aegis motion presets: micro-interactions only, 150–200 ms, gentle ease-out.
// Anything animated must go through these so the whole app moves at one tempo,
// and must live under a MotionConfig with reducedMotion="user".

export const FADE_DURATION = 0.18;

export const EASE_AEGIS = [0.25, 0.1, 0.25, 1] as const;
