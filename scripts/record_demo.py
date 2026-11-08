"""Record only a fresh synthetic browser viewport (optional development tooling).

pip install playwright imageio-ffmpeg
python -m playwright install chromium ffmpeg
python scripts/record_demo.py --output /tmp/acb-public --mode full
Use --browser /path/to/chrome to use an installed browser with a NEW empty profile.
Never attach to an existing browser/profile. Raw .webm stays outside the repository.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import time
from pathlib import Path

from playwright.async_api import async_playwright


async def record(args):
    args.output.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).resolve().parents[1]
    process = subprocess.Popen([sys.executable, "-m", "agent_circuit_breaker.demo"], cwd=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        launch = process.stdout.readline().strip()
        if not launch.startswith("ACB local demo: http://127.0.0.1:"):
            raise RuntimeError("demo did not start")
        url = launch.split("ACB local demo: ", 1)[1]
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True, executable_path=args.browser)
            options = {"viewport": {"width": 1440, "height": 1200 if args.mode == "poster" else 1000}, "device_scale_factor": 1, "reduced_motion": "reduce"}
            if args.mode != "poster":
                options.update(record_video_dir=str(args.output / "raw"), record_video_size={"width": 1440, "height": 1000})
            context = await browser.new_context(**options)
            video_start = time.monotonic()
            page = await context.new_page()
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            await page.goto(url)
            await page.wait_for_function("document.querySelector('#error').textContent === ''")
            schedule = [("work", 45), ("injection", 90), ("approval", 90), ("interruption", 90), ("catalog", 45)] if args.mode == "full" else [("work", 15), ("injection", 30), ("approval", 15), ("interruption", 15)]
            if args.mode == "poster":
                schedule = [("injection", 0)]
            results, captions = [], []
            elapsed = 0
            for scene, seconds in schedule:
                await page.locator(f'[data-scene="{scene}"]').click()
                await page.locator('#run').click()
                await page.wait_for_function("scene => window.acbLastResult?.scene === scene && !document.querySelector('#run').disabled", arg=scene)
                result = await page.evaluate("window.acbLastResult")
                results.append(result)
                # Scroll the actual page to its decision + evidence panels.
                await page.locator('.scene-header').evaluate("node => node.scrollIntoView({block:'start'})")
                if args.mode == 'poster':
                    await page.locator('#steps').evaluate("box => {const row=[...box.children].find(n=>n.textContent.includes('Unprotected baseline'));if(row)box.scrollTop+=row.getBoundingClientRect().top-box.getBoundingClientRect().top;}")
                await page.screenshot(path=str(args.output / (scene + '.png')))
                if scene == 'injection':
                    await page.screenshot(path=str(args.output / 'poster.png'))
                    assert len(result['receipts']) == 1
                    protected = [step for step in result['steps'] if step['label'].startswith('Protected')][0]
                    assert protected['decision'] == 'BLOCK' and not protected['executor_started']
                    assert await page.title() == 'ACB · Permissions before execution'
                caption_start = time.monotonic() - video_start
                print(f"recording {scene}: {seconds}s; observations captured", flush=True)
                # Continuous video from the actual viewport, no canned decisions.
                if seconds:
                    await asyncio.sleep(seconds / 2)
                    await page.locator('.evidence').scroll_into_view_if_needed()
                    await asyncio.sleep(seconds / 2)
                captions.append((caption_start, time.monotonic() - video_start, result['caption']))
            if errors:
                raise RuntimeError('browser script error: ' + errors[0])
            await page.locator('#shutdown').click()
            video = page.video
            await context.close()
            await browser.close()
            (args.output / 'observations.json').write_text(json.dumps({'mode':'offline proposals, freshly executed backend observations','scenarios':results},indent=2))
            def stamp(seconds):
                millis = int(seconds * 1000)
                return f'{millis//3600000:02d}:{millis//60000%60:02d}:{millis//1000%60:02d}.{millis%1000:03d}'
            (args.output / (args.mode + '.vtt')).write_text('WEBVTT\n\n' + '\n\n'.join(f'{stamp(start)} --> {stamp(end)}\n{text}' for start,end,text in captions))
            if video:
                import imageio_ffmpeg
                raw = await video.path()
                # Burn readable captions into a separate band below the recorded viewport.
                filters = "pad=iw:ih+180:0:0:color=0x0f1512,subtitles=" + args.mode + ".vtt:force_style='FontName=Arial,Fontsize=9,Alignment=2,Outline=0,MarginV=8,MarginL=12,MarginR=12'"
                subprocess.run([imageio_ffmpeg.get_ffmpeg_exe(), '-y', '-i', str(Path(raw).resolve()), '-vf', filters, '-map_metadata', '-1', '-an', '-c:v', 'libx264', '-preset', 'fast', '-crf', '25', '-pix_fmt', 'yuv420p', '-movflags', '+faststart', args.mode + '.mp4'], cwd=args.output.resolve(), check=True, capture_output=True)
            process.wait(timeout=5)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--mode',choices=('poster','overview','full','all'),default='poster')
    parser.add_argument('--browser')
    args=parser.parse_args()
    if args.mode == 'all':
        import copy
        async def both():
            modes=[]
            for mode in ('overview','full'):
                task=copy.copy(args); task.mode=mode; task.output=args.output/mode; modes.append(record(task))
            await asyncio.gather(*modes)
        asyncio.run(both())
    else:
        asyncio.run(record(args))

if __name__=='__main__':
    main()
