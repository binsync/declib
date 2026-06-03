import math

import tqdm


def progress_bar(items, gui=True, desc="Progressing..."):
    """
    This displays either a text or GUI progress bar using the DecLib GUI backend.
    This assumes that the GUI is already initialized and running if in GUI mode.
    """
    if not gui:
        for item in tqdm.tqdm(items, desc=desc):
            yield item
    else:
        from declib.ui.utils import QProgressBarDialog
        pbar = QProgressBarDialog(label_text=desc)
        pbar.show()
        callback_stub = pbar.update_progress
        bucket_size = len(items) / 100.0
        if bucket_size < 1:
            callback_amt = int(1 / bucket_size)
            bucket_size = 1
        else:
            callback_amt = 1
            bucket_size = math.ceil(bucket_size)

        for i, item in enumerate(items):
            yield item
            if i % bucket_size == 0:
                callback_stub(callback_amt)

            # close the progress bar since it may not hit 100%
            pbar.close()
