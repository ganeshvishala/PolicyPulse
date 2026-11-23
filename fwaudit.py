"""fwaudit.py - offline firewall change audit, one file.

Python 3.8+ standard library only. No internet, no AI, no extra
packages. Input files are opened read-only and never changed.
Results are written to NEW files in the output folder.

  python fwaudit.py           open the window
  python fwaudit.py selftest  built-in check, must say PASSED
  python fwaudit.py run --algosec DIR --rfc DIR --out DIR
                        [--smax FILE] [--date DD-MM-YYYY]
                        [--operator USER] [--config FILE]

Add the file-name part of each firewall to CONFIG["tabs"] below.
"""

import argparse
import calendar
import collections
import csv
import datetime
import glob
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import posixpath
import re
import sys
import tempfile
import traceback
import zipfile
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as _xesc

VERSION = "2.6.0-single"

DXC_LOGO_B64 = "iVBORw0KGgoAAAANSUhEUgAAAJQAAAAYCAIAAACTLEMgAAAN4klEQVR42t2aW6xeR3XHf2vN7L2/71x8y9UmcRLn4ti1cYKpoCEplwRCEy6V2gIVLxSEKt6K+lBVfa6ExEtRpdKq6UVFvQKFSCQlAXMLQWmaqAR8x07A2HGCE9/O7dt7z6zVh73POY5zbB8T5EoZbX2a/e09e2bWf9blv2bkE39zkuWVSC6trryuvK6srnzU1Rf/9Lr0OnoO5OApkgM5eq7GhuOXr155/Q0TGzcXl10B4Ibo2R2YocqRn9gDf6rDcSZXsuYq1t3EtbeybiPlAMAdfIm2r72c+WU3ThzihT0cO8DUMZs9rtS+5Xdl871YRsOr2s5P5+QL7H+Cg89w/DBTp8iOOeY45pIlZIkZzcQkIROyBJOY6Ovzf8b+lpAlZGKWkAmtxEaqWge1lCMZNFLGZc6s8FR5XdnoDPC6a/GfwttAjp4COXgOpB7I2YbDJ+eePzj33zvGN24Zf9u748rVS+MHIFoIeZbpEaOXeHE3T32VNVf7hjfJrXdxxfUguAOI/KpwwzvYhOljHHqSQ09x/BBlwJ3sNJnx8pzduSHq08flqQfZ+zhpRDLa7D7fQrqVIV1XiMzfzK8ZwQVHFp464oiLgLj0dUNNgqH9JSEizkIXS8oSL62pfDTwuqQeeD3wuqIpva5YxC+SguTgWUmRHCRHz4E2kNVyttS4F6Ryz5Mz+58e3vvhctOblsZPICpoPyADFWZfkgPfYvejXL+NrfexbnMvNeS1QtiNQYSTP2fvo/z8KSpoEu5W584gaIgIZwj8Vc0P/o889g+kWUaNZfCs4LLQSDrUHHEwwcGkR8XmsenqhrhoB5WjJuoijrooEk2CSTCNJtFEY4jDs0THGSgGcmV1JTZwr8wrt4FYZbnyNJC2srbSpvIU8OBE94AH94gHt+gWILh7TlgOpOB5am5uTEy++le5+VjYdudS+DlVxAwcVYIiGE5rKsKxPezYzXXb2fpBVl9zTgu8TDspgiij0+x9mAPfphRSS8LcUFHHHHGcJMVQPC+N3L7H+N4DtNlSp1imBCxrDH377AgBDQSXmOnMY+wMY5SYJARilhC6p4QkMXSmVUKSqASkSFKpDlQqkYFKJTqIa4Z1NxIVQMxdRQBzD3hpdeVtSV15U3pTWFN6W3qqyEX2Co8eopdKUFL0qJYihZLULYgpSVKr0/XqipysaVO01iRls/C1z/twKLds713dQilKJi4j1bSzDJSoZCMbKibQGsH1F8/wjZ3c+h4230esLh4/x7zv9NnH2PMgPkNK1qKAOK6qQhXVndnWqnEpJryakFcjd+gZvv8A2S2buDuqMSBiDTq2BhTLGJbxEAxNREN7z6fR0NbFNWZics2oh2gW0GAoEh0VVCUGLdSrEKpIUUqJlBIKyebnmqIsTHWp6c8bgwWD4q/S2z4MyVOn2mf3tE9+c/LU0el6LloK4oVmxib41F8wNtnZ+kWFsERqmDvN8cP+wl4/slPrYwS1Oqkq4oaoOuMVgyvY9iHWbgWwjOrSxm3p4OIwO7/EyX3UieR4B5vQLUUZ46pf48rNrL6WwQqKISGeIRJHYDRtX/4znT1FY25ZXCmUyXW+7T2yfgvjq9HARRj1RYH68l4Wd+eSFE9t2vHvxdOPpLYN3oooEwWb7+a3PnEB1cmJozt97zfk5X2o2MjAVMRUtAzgXHcHmz/A+GUXcIQLKp4aDu5g/9eRxGyLGNbF00qhDNZy89284XbK8fOvAH/iX+TADptqJWd30ULZ9G7u/AihuDQiFTO/CGuzzPXzai3tHYz4Q38rP/4mTUbEomo14A8/x/iqMxR3fl37fBy4EJof3cWehzh5kDaR8S4cA8YrGHLLvWz4TYrhonzPHFT3qhtHn2Hfw7QvMz3CHc8geGasRFdy6/tY/xZC7F/uolCRVwyvK3Mn+Y8/sdEcyXC0DH7z2+WdHwfH7DWSmWVCcuk0rydSOdnnP60zL5kbEnQ8+js+LlvftTR/OrPhAgDPPsbuB8nTzDXzi0UJwrBEV3DTO1l7OxNXnP2Reppje/jp48weIWXqhBtmiFMprXHzPWy8r8f+/Ba4G+q+7/DkF5hNlrOq2NiV+tHPoOFXEAAvu0QuWRHBjFjqW+/n+/+srRGEoHJ4N1vfdb4Ji8x7VUOUDXexdiu7vsqhHyBCkxEwYWQUUzz3dfY/wor1rLqWwQok0MwwdZRTh4mJlBilXrMRCqVUJm9gy++wav2i1T3XMlocD35krzjW0bSg+sb3EIp51HndgQeI4s6GN9q3vyBiTlDcTj6vy2TcC+mP4Sre/DHesJ1dXya/zEyLgSimzDkKo6Mcfwm0s9Ukw1rmDMuLAcFkRYpsvJ8b7lrUtmWZOwHkxBHaRHbNRnbWb5ln+rxewQOE8TUMxyTPiiigaa43RIs5ieVBuHYrV23mZ4+z5yGaORykk36gFZIjGTppGu7zXtBBKCLr7uLGu6km+nzN+bXtLHboRj1Dcu2zCkPGV8+7xktXLulKWYBQRRAxHAV9DU6il7v2dLu/5s3sgrE1I8/j50DGnbbt4RRBLr5fE9wtGeZmly5y+P/TvC6AnDpu7Zyoa5dAqcZ7c7pMCPuElnL0R+z+Cn6auu2zaJ2RVKgCRei7Q0nOyDDrSaRn2oYXvsehx9n0fm58JyLLpYmdemmgHMPp887tjMwcpxoCyOsWPEMDh3fpWLQ2u4oWwVeveyXHP29zBFFmT7D7Kxx9CpS2Q11BiEoVaYThOlau6wOWeopTR2h+SqzJxlzCDTdOzaHO3i9x5Gm2/h5rru89X6+7F7KcK67m+CH1jIsWwnM/5rJrsIyE1yN43ZxTyw8fIWfFe3u17tZFbnc+qtDFO8bB77Lna8gsdeqxJFDAIBJWcf3bWLuN4eqzP9JM8+Junn2MfJAMTbdZg0012h7g25/hpnvYfB/F2IWpgjuCX7NZDj6BebfvY088pLfdQwgXYUJ+RST9l2TfF6lzCsKOv+cn36ExU9eolEM+8lnGVi5BUpcg6T9mz0PM/Iw6YT3rx5XJATLOTfdw3R3E6nwkHXj+f9n1IKMXmW3MRDBxAWOsIqzwW++XG9+GnkXSlxLAzEke+CM6km5QBt9yt9z/yc6zuqi8Bva9TGFfQpKeW77/b+x6lOyOeQg6UfpN75I7Pnqh9FjD0Z3s/yYnD6DKKIMjIEIVcFh/B5ve32vbedJjbn0sk1v2P8rehyHZbEIMExCNQlSGa/2md8h1b2YweQG/+8jfsetbzLbkbIgWZd7+3nD37xMvVXosm8sylsWZKWdZ/jJysMz0CQ7t5JlHOX2E1lzMVbQsbLhCP/TnDCZfwZDcyQ25ZTTF6cO8uM9e2KnNCRSbbVW7JLYiznhFdSVbP8RVmxcjT1l2YvrU8/zoixzbTZMtzROJzoGJwpCrN3P1Ji6/nrGVfWJ6wQZ0Rn52ir/+NDOnzcgekoZhNZhZeU18yz3xhk1hctUZWruEFP0c23BLZquXfvaX/7S79LaiO82QSpoij0qawlvtNupoFYueAh49KxYsBbFgScUiSbFouXtHuqekIJ1yKJJt9qSWgjsZ1AmBqBRw7x+zftuiNLvKiZ/z3c/R1jaa1rGCoDTJkuliROqMF1hg43u55b2E4qK3hDrO0CHx3A/sh/+pNsVsYy4kU7DsKk4RMWe2sTim4+Pc9ttsecdiGq9Lc+9/2r/42ZxjbZjEFGIZyhCLE0l9Yo3FmFyNmDWaaGvBNCTUJSaCa0iuSYvaq0aKRqtWqpGWjZaNl40WjQwaKRsp8/wSUOn37LrfODdr2Vq8wRvxWmwUvHYfmSfx5GRI6lk8iycha3/KoT/iEBduycFTIItnPCHWx+4qittINIgJqKo6Ae765CuQWyipoTlFyirYXFbJJjZ/lMBlGGmNK29n8wdYsfaX3IwVQeYjixvu0LVb2fWw7dmh0WiTmZCzudM4ydRc6ilofG76FVqkihu3bLf7PiX/9Y9qOnI1CyMkZ1xEZ2eM6LJ4JiVLnD+9krr92EarkVArI0KtsZZYSznSqpaqlsFIBo1WGT0X+Y+0M3ht3rjXZiP32rxO3uDZSebZyOY9MNnbSM6eAyl5juTk3XGVefwsBSx4DuKEbodXEFGVfvtzGIljvP3j3Pjr5zgGIbSZzg3R70VLqVRR5lou38rGe7ni5jPC+l82z7CwzzCYZPuH9ca72PmI/eQHGjI4o4SZmZuZSqDOSyQ0RHELt7+9HUzY1/91Mufjo5SISTRLyCaZYBJaJIskNItkJIuYSIs2EmuKWoray1pi7VprGInWrrXoSLUVd6vPRxXETc3Uk3hSz2JZyNIxITfF1E0w7euIu+DqKH194Rdc+tM0nXUSOp1RIapGIQ645U7e/EEm1lxAY8Q1KEFRoXYbXqnX3sZ1b2X1+t5B+LITWhdOtjnurFrHnX+g297HgSc58KQ9f0BVFDChbpBClozsRHErNm2XdRtGjz/ie3eW5pgmI5kk0ewhiWaPWWL2/gBES1FLVUvVUNVSjaRqelWrGqlGUtUySMReeucBTzs31sGzgFaHBx0eXaXnW7K4b+6vdKzS+9eFTXYHEQMdm+TyN7DhNjb+BquuvoCt6xh3HNjYCp24kss3cPVGXXMDsVzkfGcHAq85XyfSf3nyCm6/n9vv11/8lMN7OLyfl45w+gTN9DlTiaK4xZWrJ+77SPWWYzP7dtbPPZtfPt7O1j1aMn+Oj5AlNlLW/Qm+avHqTWWHYmUd07/QHP8PvEww31vjpZIAAAAASUVORK5CYII="
DXC_LOGIN_LOGO_B64 = "iVBORw0KGgoAAAANSUhEUgAAAOYAAAAlCAIAAADZdAL2AAAZiUlEQVR42u2da7Bd5Xnff8/zrrXPFd1lXZGEJEACiYtNsPEFG4gxuHYKceykmTZNnXb6oem0nbaup5O2GX9ox502mfaDO54m48nkSxzbsRPbgO2BYHBcY2IMSCAJhISQ0AV017ntvdb7PP3wvmvvfY4kdCQEljLs2XNm7bXXXnvt9f7f//s8/+dy5He+fJwLfQg4KFZ4XXhVeF16VXpdkLcLr0uqwqvC6pKZbxXU6jFgiolbwAImWHAL4uXwwOCcK4YWLR698srR1WuLufMA3N1dVGd1fe6IcHA3X/4cZcHQFYyMMmcRi1awdA3L1jNvCaFoDjYQRLgUH44ZqtBc3uQxjuzhyG5OHbKTrzN5jE5bQ9vXf0ze/WnckNnfIvJpTx5mzxZ/5Xk5vJcTh21yTGPEHQMHdzy9EpPgqIlGxAmGmqihhkZRRy2/q45GCYZ0DzDU0h5C3ikaUcsHa3d/JUUlrShFRVlL0ZGilrKmKM6IwtncQwSH4LEgQbAqvS4ayGZQJnRSlaS3qiJv1IFa3QKmbkrz7G5blPHKJ8fqwwePPvfUEQ0jV62Zd+Otg+s3iEgzfrN+qGA1k8fonODkAfZv5WmDwJIrWXEt697D8msoB/MQ4rMd77cDq831aAA4tof9Wzi4jSMvE6coFBGtjWhmTquU85pyXWTv3epbHpGXn6EzKSrURm1q7jR4dppt700bEDCmf6OLC96gyLsHOpkO8hWK90EJBMRFQNL5DHHUEUNMxBBQUBctTofirLArgBceS89w7CIys2kD4rzTq0zD1IVVSlSm4VXcQtrppphgmNcevXKR2BIvdu8Y2/Xc5Io1Ix++t7VijbtLlx7OsRYIKogj4E50DBNXjRzfx/gBtj1iIwv02tu45v0sXNU3RPILZlZPk0fojLHnp+z+CUd2MlhiToxEt2i4I45xntMs4UQ59BJP/gUvPy1FoF1Z7ZpwaDMhIP34kC5tCeBIwqgjfZiWvg3yD0G99754Bq70XVY6lST29Qxc9UzSYvRBdgZG/RwmgRdetxIQ6eNX7xRet6iDV2WPcRuK9bqgDpgQE6eGHsXGfpYNboIFy9SL2bhVwW3OvhdPfOX50ds/NnT7J6bxxBs/gjSLviPmQRRBxSxqBZhOHmXb92zLQ3rVzVz/UZZfh/ziTAV33NCAiJ96TXb+NXt+ApNEc3OfqEFwV5DEcQ7KjLE/t70EPPkX9uS3NIhVThXVEG3MAHH303HhgiQa9N5ez1fQw2vfTRNx3FF3XNx7SJXpGE0b4oi7uoiLZuAmos1cq9Mg62cxVc+wzLql5b7lDTSpC8t7Cq8L72RLgLq0qmstBKK6qVsgSoJmzySI/RZCD8reoNlM8Ym2FWIDTzw0tX/XwKf+uZQDs0KtNkuPgoiouICICuCuOE7HVIwDz7D3575ik9zwCZZt+AXYuOnnSKB9yrc/6Dsfk6KmU1udQYGYuOThbyy08z5/1ebhL3HgWepoNSIu7p7YOp+xYczpiHBwoQ+O/bB1R8nI66Ew2wBCQ5k0PIrlc2arwJtp0bV6XdQkUWzo2riFiIsI3UnV5XTpm2giPWfL65JqACu8DlIVVC2q4LGUqqQu6QSqFjF4p5BqwK2QGKgKicFN8CAe3BRXXEHN87aQIFuk3y0uZhniRJUM34BhdmqqnvvK1vZX/1fr1/+VlAM92jibYRBKxPJNVqxZb10l/1QBMROhY6omR7bzg21c8342/Qqji8+Dzt8kuQqIEitefJidD4udkrqiA5Jx4smc7OMSTwTnqiEgcq6L9IzX7/0hh19gstaevZzGXQATcFUVcDNHSJMaw8FFjOCqeclGLQNOXcRQQUVCZn1RR4TCBKEQVCT5FiqighqKKAREuzaAE0QKpHApLL8reSajRWt43uz1gWS8tqgKq0oPJaH09KxKpHAtXUrTkqp0SpfSq9ItUAYPSkzc2QDR1GNAuvZAQPKGizhuXtd1RVTzYKYSQ9eEMB+bZPTV5+s/+x/Fb34OLd6IbaxmwCkC5mmA1IwQGvbFpVnNFMRcxDum4rz6BK/8zDfeI9fdSyin23EX+2ExO1gHt7L1m0y8SjszazKsRXpLoScj0kXFpFCCoIrDaItq6hzGsZs/9Idy9AWbrMRMxPtXUhNRTEUp8sKilsDqSTRQF5VQkNFDA7hGQEhEGGI2PbsbapK2Q0RcQnQ1CV2twCR0N2oJFa1KyiBlIWWQspJSpFQpVUqhlK//ZPI0JeBsq2t2kkIGXwzNgh6IgVrdFROvCzx4VGLmRVxxcRNc0nZ6ztjjUSDtp+rYySPxwN7WxLHBIONTUyIePH+v4upRVFoD4pvvkI//0zOzYGLf8WP87AGqSW+P+9gRPXXYpk7qSIlDHRE1R9QS3SIiIq7uLiqKOoMFc1b5pvtl2fVvCd12l4iJo2z9Jq8+AdCx7ALinsix6+244sZAQaG0a5MBHZrP6CIGr2BwhHddz/LNZx5GN0T9x38qLz3KeOUx4i4m7pbOT4TBgk5keD4Lr2TeEkILs+zv42nu5GdjkhqNkySkdd/Q7rvJ5fdpe7Tvs6e/lCSBRQoTrSU4eSZ0/8p0i+ASUyOrTvXKzurpv7FtT7bU2nUMXmcmFlOLqkoJn/k86989W+WrmvKj++TwHn/1WXltJzIFThUNFXEEQV1MUM/3RnVQMWftB9l0P0Nzp2mZF0cTcHY9zvPfgknGOiboNA9DHBcBFwqhFWy8o/OvYtXNLLiKeSsYnDer70LYt4Xv/09qtzqKe6O5uptqAbWx4YO+8UNy5UZCecmiQmL0WbLs7LSE/rXzwieDiHhjQwPVzi3Vg38yPH5kslMVVotbkCg4ql6ozF/G73yR1sCZlankgIucwYsaP8a+Z3jxR5zcRRFsskI1WwrdJVNwUBWGSnSUzb/KVR9403TbBSuc2MvWr3NsJ+2K6D1ffJp8I5RCGQjzWX0rK25h/pVnWvQd0TPfAYEY+cbvMXbQ2iZuuGOe/alWYGgRd/wTVm+eecLzCCu96VE/XUY94xuXMsv2HANRGzth3/pSsfe5ut0piCT7TiEUDAZu/y1uuadnEZ5DQmr0+e7o7t/Ccw9xZAdBrB0RF++iViQJ4TS4WbCBTfezYA2AWTInLgSsnTFe+AG7H0WMdo0ZYjnOlI+UrNC1CgYWsv6XWX0bxcCMOzNLlcBfeFx+8hWbqBu8gru4UAbedQ33/EtG5uLWuGFy6bLsJQ3Z6d6JT03YH//HcOxVast4FQhKWdjcpfrZ/04I5x0C6NewDj7n2x+Soy9QRWpPoZyeFg4GKspQoHLW38HVdzOysDkJmchnA9ZYse9vefH7xBNMtHHwmO1FuqgVcIZbMMKGe1nzforBfCvOSKVvKER4rP2b/0VP7be2icckvoo7ITB3Gb/2+wwMz2rCvwPZ8/apX93Jn/wnvMZw9eQtEaAIfOY/s3LjecdyezzUAG73/2PrX2LHfbzjqIhJX8QxOQoqznALH+Cq21n7YYYXzlwW+kXtfijHDnv/ll0/pDpCVVMZYpj3LcQp8gSDShTW3sE1H2NobnMH9Lxt6GTAHNzOg1+0qpbYJAqk7BAp5NNfkMWr3w4V7yI9Ci6XhwYssmI9N93J849QGW4oLkgoaAXf9TNZufECTak0Wgm4V93GihvY/l3Z8bAEt7Y73qW1Bn3KRCRMsu9Rdv+I5Tey4j0sXEc51AcpmUZ1J1/l0HPse4p4nDrSqRshQKZJ9R4onUKYu47Nv8b8NT2wXhgFJkP25acolEoh5jukSkvl2rtl8erLhV8vN8hmYDnv+3ts/SGYSA4EpDi77H8R9zd167vAbY1ww2dYcQs//6pO7mGyNsuxnga5ggiegGsceZZDT6MjzFvNvCsZnk85hARih6kTjB3i2F7GX2OkRaeiitMEhxnB++ECBrn2k6y9vceRb+ZHacCd13YRDfMkTrsjZnREbrjr0koD+jsHWQFYsNxXrJdDL1CbiychV6Nx4iDtcQZHzxEMm+XEcGfhWu78HLseZetfalEx0QHNaEvWZIqhmTIZAcpJTr3E1B6iEw0k2dmYU9UgjFe9YECaaT2ZRmgFYmTxu7nu7zO84Dy8q3M+OuOcOEAnYgZgrggtZcE65i1968Ij70C25y3Jyms5utMc8YiIpthPdYqpMQZHL47CknJoNLD+LpbewPZvs+8JQqAdQbJN2Q9cESrBnXaVjWlxotOpeqGY5FpN03Ecd1pKqRQL2XQfSzZdzIBFmhtTY0ycdDMhzxNDVJWVG9+S4Mg7kJ05BqrMX5KSWnL8W1xQVJg6BUsvIqtnTXd0Mbd8luXvYcdD2D7qlCOqiDYbklMcu7yYcdyV1U4XGZuXITA4j1W3sfYjFAONgnGxMOQgTJ5AxE0kqVqeYcucxT1j9x3IvrW4LQckRQ9VXBAREzTlcXfH6WKZIhJwA2f5jSy9nie+zNEXqWJGauJXaVArXfbVRjOw5pIaPZgmYcqcIBQD3PyPWLgOwCPyFrhBZt3EKnfDUHGieWjJZTj6lyVkpe4Q1ELKJcQFVGaRx3RBpN71TvY/zY6HOLkf8yZ80MVrn5IlTAsdJbhbkzPQVbKynuVUkZ/+X666nXV3Ug5e7FzHJG8UyfFyTJopoyJSt3kHsm+TB3b8UEKJe9YNVBwzhudwEb2J7ho99hrb/opDzyBCjL2J0UvJFNzRhFoFhxpL88mymBWtm0uVIeuOp+KqE+x+kL1PcP39LL/p4tuXg1dYbYLTFDFomkXHD71ZV/UdyM5Sh7J92zXxVjIMghA0DswJg1f0YP0mTcAUqbLIzofZ9l1Kp1MjoafPepdQQRR3glAqRaCKREEdhbLEjKomxhxBc+sjWsedKtKpaR3giS+x5D3c+ClGFl3MXMfBUQZHZWoMDJccrRX3V3bIOSJ270D2Ivi/cOI1PbwrR4wSQDVQhjBvKa2Ri0OuyTY9/CJbvsbkfuqKTvK0ukGyLp6EIAwGOpEwwtxVzFnO8ALKQVDqKSZPMv4aR3fRPsCQ0o5YbEi3y7UG0AGHwz/n4W1s/CTr78wk/WboNk2wgRGds5Rql1WuFnM0uO2yfydHD7Bg6SVQ6PZ3FrKGBH/6+1Ji7ZzWjGCgQXjXOkTeVCCnawlMnWLHd9n116jQTsUC1iSE52TAnOQwEKDF4htYdjML1rxRzt7xvRx6jj1PwOu4U0ekAWufe+/jtYYxtv45rzzpN35aFq2DCw3VZt8rooFl13BklyZvMFXNIKjxxHe495+9VW7fW7TQXjY5BolvXnuZP/s9sKYYRkTEFG0VfPzzLNtwIbSUfayUX+6+6zF5/tvIOBNVU4KnQJ8WqwgMtdARVn+QVe9lcO60U81QXumLCMQO+5/hhe8xvo9odBpvrBtZcBDMRAcDUVh3Oxs+zvD8CwduuiH7tvnXviC1pYQYN8tzUEt+6wssX38ZxWwvp0wu2hP8+e9zYr9F00YocBEdKJi7jPu/QCjOb42b0bXg4FZ2fJfju6kjVbfSrhvxahz54QFqYc0HufpuBuc09Hw+mVxu/soTsu07VEeZ7JBKA/J4NId6UIyREhtm40dZfwflUL4V55/JRYx85T9w8iCdiEU3lyxyB+Yv47P/jcF3MrkuosaUWGr8hD/wv+X1F+gY6ikNG8VRHS54/2e55kOzo9jTsqHd2P8MOx/hyA5UmDLUpuVjSVMalryrBRu5/j7mruizJS5oklST7Pge2x6gFCajuWk3u9sRlzQPNMBAYeUCufojctUHGBjtM2Ma/+yNLyBh8WcP8fifMlnnZANvfmFZ+qpN3Pe7MnqZ5MvGaGcX9LhYOeYzOorMym/oJ609W3jkj5k4Yp2omVwdEVfVltroEv3Mf0XDWasSegWk098de52DW3jpx4y/gohNVmjKMJh+YGLZkRY6h+vuY/X73qwO1Q/c4/vY8jVe304dqT13cKJXRigQTULKLtc5rL6VNe9l4erT5mFjVZytKqHq8Eef48Qhqogb5u5iolGKVqusRhfrx387rNvcfMJnVl1f6LD7BQDkMmbZuvK92+T5x9j+NxRCxNUh6eCYiJYFwbnn37Ny82yDXp1xThzwo7vlwFYO76SIRKNTQ2o7IdK0CBARcxRlUKmd9R/muvtpDWd+uohSGrD7xzz7dWzcxjuAJhfPmxrBlKJYiwZoFYx3bMFqXbmZd13NolWMLJitRbvzKb7+RSqnrpEQm6YstRStEDqmet0vFTfdXqxaL2Xr0mXZH/z4YNPLLQY39TrgSlSPgajugagetVco2y2RNWn2pELZ5oCYEpyaMloHC6Tbnj+rbtOKbLutJJLcqUrs+PGD8vpeJo9RKu1ISNSbnHVxRTQwUrL+Tj7wD9+wwvYozz2AVbTHbPwo44e1M8bIANGoajPNQoD0WlA5yZ0mL8ojK/WGT7P42osv8tNXYTt+lK1/xa7HCWJt09R6DDzZHua4u4GreqQMBKUTocXgHB9dxPA8GRhk5WbW3XKWu2GI8uAf8ezDsR3dMHpl2VGDu4wMDE4anaG5unxNmLPQyxIJqZWGSdNrCKaXxTZ7moYuQOoeF+lWfgfrVY2HOK1oNpWDBxM1Cd5POz69+0sTtCme3j5VULWaplrdjdKrkrxReB0yiHvtW/orwnstiTymjlpClF6zgqYBTIZ+zBEgDI95I7cOQTQVmEq3pA6jyUByaZJkXUQGCxZcw23/oKkpOMtj6iR7fkgIWFSDaLjYRJXD7moz7hKOp24WIy1ii42f0PV35YxEuPgx4a49PbKA9/42a97H09/QsT1M1eapPAvcxHI/F7zGxGINikWlpjMlp17DneFBTFl3y1m/yJ27/7EfPhj2vzDVMTNy00IP5mqEYx03l9Inwp4XRXfTa02QGhj2tSbo61pgaOx2KnCNUtRSVFLWUlbdJ81fLWspO+mlSC2he4ydZkWcsV9R0Zk87tZxavPKqNzr2ivzWHl7AKutqqjU69RuqCCquzQNCroNiApc3EKmz6rp7ELuqEUdcHVXmpLuBGuzQk0snc0JOd/fRDTlDKSEZDEBSatlgpWKDpUsuoZ7/g0azmESaLBKtV0ZKdfK8nzIt0TAPZcmiqbi66HCKpOVH2DDvblI5q3O0Otmly/ZwEc/z4uP2pbvaDme9IQYXVOBjedEBXHH6jSeZrW6oIGJinLgjexFN0Ipv/7vqq/+weCBl061LZqANP00xdCoUjnWdg8xsYtTGImEzLAo6oSIOhZFjZiacpqEKBIpokhHvBJq8RqvxSvxGq/EarFarEMdJUaJU1LVFFFalRbedO/rWmXJpOa0l4VYxE084lEw9yhubrViTvrGWjwRp7mbJ7Rlmsx86W5ghqUjm8Qlc6I3nQzFo+Bg4hFMcn84zx9xwxRxLOGGphcGqQVVagNpKOo6VLBsE7/8u8yqJ5fjdcpV9WnOSs89cBBRxRgqmKpYfJNuuJuFa7Mghcjbk1EqmhvIXXuXrr6V7Q+z7WHiRGi71ahhlrwi78LXHTHHLcVgc0ecs85exY3WYPEb/7b9jf9zxd4dRyfrSHCR1MQl86WrIWbJ0pXuImguJhK910Az72k6vUUPHSlrQk1RUdaUFUVNmRrEVpS15z01ZUeK2suOlEZwk5lOmE9rjNfX044iLdbN00O3B5Zb8LTcO9IzWCW5BZLXLMm2n8u0Ho1ZQ2kO6BU6i09vUOqNQDjNQ+/G75OUb46qBnPTwUB0bvgVbv3V2ZKfZyWq3yqSpsOYOahpESgDFSy6iY0fbVIBrbFU3k7nQrOeMHgFN93H1R/xbQ/79sdVjmOuU24uGJiJd1PDwBy1BKvZzAopBwZ+41+3H/s2P3pwKJSnKq89tYLUvpZEedHP7Nt0zIy9/d0uRmKEbAzQNQmKWlqVFBVFrd39RUUrHZleRsJZBu2sykKR2C49JdOhq5u455e4uk/Dpbi4iac9TUVU7pOTvVzpy9AkNzuZcT0yXeHIYdAcghLEU2tCyXrXgGrtrNzML93P0vW9pmuzMhcdR1UNwzUtMapCK2ihVLUNLJDVt8ra25izvDepf1G5+t00BjNG5sktn5LN9/DyUzz/Q/a/oCUYtN2jO44pHj05QTo7SUk0rbEDt39S1m6aeOyBgX0vD6iOdWKtYl6YkLzdSLCmD2Hsde7uNdrORq2EZKrWUtYSKspay4qilrKirDW34U4YraVVNbA2RM5TRnUoFE8Lt0rXkbfuziYxmaamP8O0WbRzYh1J2sdm9qj1vu653eFoMp0lK4DJlDTpXX/THi8IhWJOa4hVN3LDXay6kDoTTWasuAYlKEBt5qXOvZKFa1l5ky5an9MD8ky4FIR0yWa6OwMjXPshrv0Qx/bz8jO89DSv7ZL6lKgShFpz0kIhs+7vIiJg1lp5Ves3/8Xki8+feuan9vKuwlxD0Y6Yee1SZyNVGwdrOgGLGlrLDESWFZlTp/Nrpt6KspIiSuGnqbazhG+RZCaFhlxNUwOIaWt97hKZoennoPCsRDFtEvVhN7OI9+R9772Zu+oGhka5YgFL13DlRlZvZs6ino1zPnh1xIshMAZGGRrVkUXMWcL8VbJgFXOW9MVMLs3/ldDcn9SfYf5y5i/n5nsZP87hvezfyeF9HH2diWOMT1CPE85HT1V1MxEZuvq6oauvq08cG3951/jeVzj8up08GSc7ZuT/fTDjHx80ElWD0SLRaiVlPQO+XeBKUXtZSVFT1tNTcGRml/pzYPf/Ax+KOE4oIJ6zAAAAAElFTkSuQmCC"


def tool_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except NameError:
        return os.getcwd()


def default_operator():
    return (
        os.environ.get("USERNAME")
        or os.environ.get("USER")
        or ""
    ).strip()


class AuditError(Exception):
    pass


# === CONFIG ===
# fmt: off
# tabs: name, layout (PA or CP), HA pair?, file-name patterns.
# A pattern is matched against the firewall name in the AlgoSec file
# name (the part before "_-_Changes_Summary"). The first pattern is the
# primary firewall, the second is its HA partner. Add your patterns to
# the tabs that have an empty list [].
CONFIG = {
    "prepared_by": "",
    "risky_ports": [20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 161,
                    162, 383, 389, 445, 593, 1433, 3306, 3389, 5432,
                    "ANY"],
    "tabs": [
        {"name": "DC_Core", "layout": "PA", "ha": True,
         "patterns": ["172_16_188_15", "172.16.188.15",
                      "172_16_188_16", "172.16.188.16"]},
        {"name": "DR_Core", "layout": "PA", "ha": True,
         "patterns": ["172_17_188_15", "172.17.188.15",
                      "172_17_188_16", "172.17.188.16"]},
        {"name": "DC_INT", "layout": "CP", "ha": False,
         "patterns": ["DC_INTNETFW", "DC-INTNETFW",
                      "172_16_188_55", "172.16.188.55"]},
        {"name": "DR_INT", "layout": "CP", "ha": False,
         "patterns": ["DR_INTNETFW", "DR-INTNETFW"]},
        {"name": "DC_EXT", "layout": "CP", "ha": False,
         "patterns": ["DC_EXTNETFW", "DC-EXTNETFW"]},
        {"name": "DR_EXT", "layout": "CP", "ha": False,
         "patterns": ["DR_EXTNETFW", "DR-EXTNETFW"]},
        {"name": "DC_ALK_CORE", "layout": "PA", "ha": False,
         "patterns": ["DC_ALK_CORE", "DC-ALK-CORE", "re:^vsys1$"]},
        {"name": "DR_ALK_CORE", "layout": "PA", "ha": True,
         "patterns": ["172_17_202_68", "172.17.202.68",
                      "172_17_202_69", "172.17.202.69"]},
        {"name": "DC_ALK_INT", "layout": "CP", "ha": False,
         "patterns": ["DC-INTAD", "DC_INTAD", "DC-INTAD_MFW",
                      "DC_INTAD_MFW", "DC-INTAD MFW"]},
        {"name": "DR_ALK_INT", "layout": "CP", "ha": False,
         "patterns": ["DR-INTAD", "DR_INTAD", "DR-INTAD_MFW",
                      "DR_INTAD_MFW", "DR-INTAD MFW"]},
        {"name": "MUM_NDR", "layout": "CP", "ha": False,
         "patterns": ["NDC_CLUSTER", "NDC-CLUSTER",
                      "NDC CLUSTER", "MUM_NDR", "NDC"]},
        {"name": "HYD_NDR", "layout": "PA", "ha": False,
         "patterns": ["172_29_163_141", "172.29.163.141",
                      "HYD_NDR"]},
    ],
    "create_empty_tabs": True,
    "layout_headers": {
        "PA": ["Change Type", "Name", "Change Time", "Changed By",
               "Tag", "Type", "From Zone", "Source", "User",
               "HIP Profile",
               "To Zone", "Destination", "Application", "Service",
               "Action", "Profile", "Options", "Description", "Enable",
               "Log"],
        "CP": ["Change Type", "No.", "Change Time", "Changed By",
               "Name", "Layer Type", "Layer Name", "Status", "Source",
               "Destination", "VPN", "Services & Applications",
               "Action", "Track", "Time", "Install On", "Content",
               "Comments"],
    },
    # role -> header texts that can play that role (first match wins)
    "column_aliases": {
        "change_type": ["Change Type"], "name": ["Name"],
        "time": ["Change Time"], "source": ["Source"],
        "destination": ["Destination"],
        "service": ["Service", "Services & Applications"],
        "action": ["Action"], "enable": ["Enable", "Status"],
        "description": ["Description", "Comments"],
        "from_zone": ["From Zone"], "to_zone": ["To Zone"],
        "number": ["No."],
    },
    # columns added after Service in every tab (the tool fills the
    # first three, Expiry, and the SMAX ones; IT Security stays blank)
    "manual_columns": ["RISKY RULES", "RISKY Ports", "PIR ISSUE",
                       "IT Security", "Expiry", "Title", "RFC Owner",
                       "Asset Owner", "RFC Application"],
    # a partner-firewall row is a mirror of a primary row when its name
    # and all of these columns are identical
    "ha_content_columns": {
        "PA": ["Name", "From Zone", "Source", "To Zone", "Destination",
               "Application", "Service", "Action", "Description"],
        "CP": ["Name", "Source", "Destination", "VPN",
               "Services & Applications", "Action", "Track",
               "Install On", "Content", "Comments"],
    },
    # service name -> [protocol, first port, last port]
    "named_services": {
        "https": [["tcp", 443, 443]], "ssl": [["tcp", 443, 443]],
        "service-https": [["tcp", 443, 443]], "https_1": [["tcp", 443, 443]],
        "http": [["tcp", 80, 80]], "web-browsing": [["tcp", 80, 80]],
        "service-http": [["tcp", 80, 80]],
        "ssh": [["tcp", 22, 22]], "sftp": [["tcp", 22, 22]],
        "ftp": [["tcp", 21, 21]], "ftp-data": [["tcp", 20, 20]],
        "telnet": [["tcp", 23, 23]], "smtp": [["tcp", 25, 25]],
        "dns": [["tcp", 53, 53], ["udp", 53, 53]],
        "pop3": [["tcp", 110, 110]], "epmap": [["tcp", 135, 135]],
        "ms-rpc": [["tcp", 135, 135]], "netbios-ns": [["udp", 137, 137]],
        "netbios-dgm": [["udp", 138, 138]], "netbios-ssn": [["tcp", 139, 139]],
        "imap": [["tcp", 143, 143]],
        "snmp": [["udp", 161, 161], ["tcp", 161, 161]],
        "snmp-trap": [["udp", 162, 162], ["tcp", 162, 162]],
        "snmptrap": [["udp", 162, 162], ["tcp", 162, 162]],
        "ldap": [["tcp", 389, 389], ["udp", 389, 389]],
        "ldaps": [["tcp", 636, 636]],
        "smb": [["tcp", 445, 445]], "cifs": [["tcp", 445, 445]],
        "microsoft-ds": [["tcp", 445, 445]],
        "mssql": [["tcp", 1433, 1433]], "mssql-db": [["tcp", 1433, 1433]],
        "oracle": [["tcp", 1521, 1521]], "oracle-db": [["tcp", 1521, 1521]],
        "mysql": [["tcp", 3306, 3306]],
        "rdp": [["tcp", 3389, 3389]], "ms-rdp": [["tcp", 3389, 3389]],
        "postgres": [["tcp", 5432, 5432]], "postgresql": [["tcp", 5432, 5432]],
        "ntp": [["udp", 123, 123]], "syslog": [["udp", 514, 514]],
        "ping": [["icmp", 0, 0]], "icmp": [["icmp", 0, 0]],
        "icmp-all": [["icmp", 0, 0]],
    },
    # RFC port-sheet reading. read_all_sheets: read every visible sheet
    # that has a port table (sheets named like Sample/Instructions are
    # skipped). templates: hand-made column maps for RFC formats the
    # auto-detection cannot read, e.g.
    #   {"name": "OldForm", "file_regex": "", "sheet": "Port",
    #    "header_row": 5, "data_start": 6,
    #    "columns": {"sr": "A", "src_ip": "C", "dst_ip": "G",
    #                "port": "J", "ptype": "K", "src_owner": "D",
    #                "dst_owner": "H"}}
    "rfc": {"number_digits": 9, "filename_regex": r"RFC[._\- ]*(\d{9})",
            "use_description_when_name_has_none": True,
            "read_all_sheets": True, "header_scan_rows": 60,
            "templates": []},
    "compliance_framework": "all",
    "policy": {
        "merged_rule": "note",   # note: stays NO with a note | yes: YES
        "edited_scope": "full",  # full: whole after-state | added
        "multi_rfc": "last",     # last: latest RFC in name | union | first
        "deny_rules": "check",   # check | skip (marked N/A)
        "removed_rules": "skip", # skip | check
        "combined_row_grouping": "enabled",  # enabled | strict
    },
    # SMAX export column names (rows matched on the 9-digit RFC no.)
    # Site-specific: change base_url / tenant_id for another organisation.
    "smax": {
        "base_url": "https://serviceportal.bankofbaroda.co.in",
        "tenant_id": "246334335",
        "columns": {
        "number": ["ID", "Change ID", "Change Number", "RFC",
                   "RFC Number", "RFC No", "Number", "Request ID",
                   "Record ID"],
        "title": ["Title", "Display label", "Display Label", "Summary",
                  "Short Description", "Name"],
        "rfc_owner": ["Requestor's Email ID", "Requestor Email ID",
                      "Requester's Email ID", "RFC Owner",
                      "Change Owner", "Owner", "Requested By",
                      "Requested by", "Requester", "Created By"],
        "asset_owner": ["Asset Owner", "CI Owner", "Asset owner",
                        "Configuration Item Owner"],
        "application": ["Application", "Business Application",
                        "Application Name", "Affected Service",
                        "Service"],
        "expiry": ["Temporary Access Expiration Date", "Expiry",
                   "Expiration Date", "Expiry Date",
                   "Temp Access Expiration Date"],
    }},
    # Reviewer overrides (false positives). require_approval: an override
    # proposed by one person is used only after a second person approves
    # it (maker-checker). qa_sample_percent: share of NO rules the web UI
    # picks at random for a human to re-check (measures accuracy).
    "review": {"overrides_file": "fwaudit_overrides.json",
               "require_approval": True, "qa_sample_percent": 5},
    "checks": {"rfc_date_plausibility_days": 120,
               "expiry_warning_days": 30},
    # Asset Owner comes from the RFC port sheets (Source Owner and
    # Dest. Server Owner columns). show: both | source | destination.
    # SMAX is used only when the RFC sheet gives no owner.
    "asset_owner": {
        "show": "both", "smax_fallback": True,
        "ignore": ["na", "n/a", "nil", "none", "tbd", "-"],
    },
    "log": {"level": "INFO", "file": "fwaudit.log"},
}
# fmt: on
CONFIG_FILE = "fwaudit_config.json"
JOBS_FILE = "fwaudit_jobs.json"
AUTH_FILE = "fwaudit_auth.json"


def _dmerge(base, over):
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _dmerge(base[k], v)
        else:
            base[k] = v
    return base


def load_config(path=None):
    cfg = json.loads(json.dumps(CONFIG))
    path = path or os.path.join(tool_dir(), CONFIG_FILE)
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                user = json.load(f)
        except ValueError as e:
            raise AuditError(
                "Config file %s is not valid JSON: %s" % (path, e)
            )
        if not isinstance(user, dict):
            raise AuditError(
                "Config file %s must contain a JSON object." % path
            )
        _dmerge(cfg, user)
    elif path != os.path.join(tool_dir(), CONFIG_FILE):
        raise AuditError("Config file not found: %s" % path)
    pol = cfg["policy"]
    allowed = {
        "merged_rule": ("note", "yes"),
        "edited_scope": ("full", "added"),
        "multi_rfc": ("last", "union", "first"),
        "deny_rules": ("check", "skip"),
        "removed_rules": ("skip", "check"),
        "combined_row_grouping": ("enabled", "strict"),
    }
    for k, vals in allowed.items():
        if pol.get(k) not in vals:
            raise AuditError(
                "policy.%s must be one of %s (found %r)"
                % (k, vals, pol.get(k))
            )
    ao = cfg["asset_owner"]
    if ao.get("show") not in ("both", "source", "destination"):
        raise AuditError(
            "asset_owner.show must be both, source or destination"
            " (found %r)" % (ao.get("show"),)
        )
    names = set()
    for t in cfg["tabs"]:
        for key in ("name", "layout", "patterns"):
            if key not in t:
                raise AuditError(
                    "Every entry in 'tabs' needs name, layout and"
                    " patterns (missing %s)" % key
                )
        if t["layout"] not in ("PA", "CP"):
            raise AuditError(
                "tab %s: layout must be PA or CP" % t["name"]
            )
        if len(t["name"]) > 31 or re.search(r'[\[\]:*?/\\]', t["name"]):
            raise AuditError(
                "tab name %r is not a valid Excel sheet name"
                % t["name"]
            )
        if t["name"] in names:
            raise AuditError("duplicate tab name %r" % t["name"])
        names.add(t["name"])
    for p in cfg["risky_ports"]:
        if not (isinstance(p, int) or str(p).upper() == "ANY"):
            raise AuditError(
                "risky_ports entries must be port numbers or \"ANY\""
                " (found %r)" % (p,)
            )
    for tpl in cfg["rfc"].get("templates") or []:
        if not isinstance(tpl, dict):
            raise AuditError("rfc.templates entries must be JSON objects")
        _template_layout(tpl)
        for k in ("file_regex", "sheet"):
            if tpl.get(k):
                try:
                    re.compile(tpl[k])
                except re.error as e:
                    raise AuditError(
                        "rfc.templates %r: %s is not a valid regex: %s"
                        % (tpl.get("name", "?"), k, e)
                    )
    try:
        _EXPIRY_WARN["days"] = int(
            cfg["checks"].get("expiry_warning_days", 30)
        )
    except (TypeError, ValueError):
        raise AuditError("checks.expiry_warning_days must be a number")
    try:
        re.compile(cfg["rfc"]["filename_regex"])
    except re.error as e:
        raise AuditError(
            "rfc.filename_regex is not a valid regular expression: %s"
            % e
        )
    return cfg



def _hash_pw(password, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 120000
    )
    return salt.hex(), dk.hex()


def load_auth(path=None):
    path = path or os.path.join(tool_dir(), AUTH_FILE)
    if not os.path.isfile(path):
        return {"enabled": False, "users": {}}
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
        if not isinstance(d, dict):
            return {"enabled": False, "users": {}}
        users = {}
        if isinstance(d.get("users"), dict):
            for u, rec in d["users"].items():
                if isinstance(rec, dict) and rec.get("salt") and rec.get("hash"):
                    users[str(u).strip()] = {
                        "salt": str(rec["salt"]),
                        "hash": str(rec["hash"]),
                    }
        elif d.get("username") and d.get("salt") and d.get("hash"):
            users[str(d["username"]).strip()] = {
                "salt": str(d["salt"]),
                "hash": str(d["hash"]),
            }
        return {"enabled": bool(d.get("enabled", False)), "users": users}
    except (OSError, ValueError):
        return {"enabled": False, "users": {}}


def _write_auth(data, path=None):
    path = path or os.path.join(tool_dir(), AUTH_FILE)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return data


def save_auth_enabled(enabled, path=None):
    cur = load_auth(path)
    if enabled and not cur["users"]:
        raise AuditError(
            "Add at least one user before enabling login protection."
        )
    cur["enabled"] = bool(enabled)
    return _write_auth(cur, path)


def add_or_update_user(username, password, path=None):
    uname = username.strip()
    if not uname or not password:
        raise AuditError("Both username and password are required.")
    cur = load_auth(path)
    existing = next(
        (k for k in cur["users"] if k.lower() == uname.lower()), None
    )
    if existing and existing != uname:
        del cur["users"][existing]
    salt_hex, pw_hash = _hash_pw(password)
    cur["users"][uname] = {"salt": salt_hex, "hash": pw_hash}
    return _write_auth(cur, path)


def remove_auth_user(username, path=None):
    uname = username.strip()
    cur = load_auth(path)
    hit = next((k for k in cur["users"] if k.lower() == uname.lower()), None)
    if hit:
        if cur["enabled"] and len(cur["users"]) <= 1:
            raise AuditError(
                "Cannot remove the last user while login protection is enabled."
            )
        del cur["users"][hit]
    return _write_auth(cur, path)


def verify_auth(username, password, path=None):
    auth = load_auth(path)
    if not auth["enabled"]:
        return True
    uname = username.strip().lower()
    rec = next(
        (v for k, v in auth["users"].items() if k.lower() == uname),
        None,
    )
    if not rec or not rec.get("salt") or not rec.get("hash"):
        return False
    _, dk_hex = _hash_pw(password, rec["salt"])
    return hmac.compare_digest(dk_hex, rec["hash"])


def load_job_log(path=None):
    path = path or os.path.join(tool_dir(), JOBS_FILE)
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def append_job_log(entry, path=None):
    path = path or os.path.join(tool_dir(), JOBS_FILE)
    jobs = load_job_log(path)
    jobs.insert(0, entry)
    jobs = jobs[:200]
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(jobs, f, indent=2)
    except OSError:
        pass
    return jobs


def pattern_matches(pattern, text):
    if pattern.lower().startswith("re:"):
        return re.search(pattern[3:], text, re.I) is not None
    return (
        re.search(
            r'(?<![0-9A-Za-z])' + re.escape(pattern) + r'(?![0-9])',
            text,
            re.I,
        )
        is not None
    )


def setup_logging(cfg=None, console=True, extra_handler=None):
    lc = (cfg or CONFIG).get("log", {})
    root = logging.getLogger("fwaudit")
    root.setLevel(
        getattr(
            logging, str(lc.get("level", "INFO")).upper(), logging.INFO
        )
    )
    for h in list(root.handlers):
        root.removeHandler(h)
    root.propagate = False
    rel = lc.get("file", "fwaudit.log")
    path = rel if os.path.isabs(rel) else os.path.join(tool_dir(), rel)
    used = None
    for cand in (
        path,
        os.path.join(tempfile.gettempdir(), "fwaudit.log"),
    ):
        try:
            fh = logging.FileHandler(cand, encoding="utf-8")
            fh.setFormatter(
                logging.Formatter(
                    "%(asctime)s %(levelname)-7s %(name)s: %(message)s",
                    "%Y-%m-%d %H:%M:%S",
                )
            )
            root.addHandler(fh)
            used = cand
            break
        except (OSError, IOError):
            continue
    if console:
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(ch)
    if extra_handler is not None:
        root.addHandler(extra_handler)
    return used


log = logging.getLogger("fwaudit")


# === xlsx reader (zipfile + xml only) ===
_NS = '{http://schemas.openxmlformats.org/spreadsheetml/2006/main}'
_OFF = 'http://schemas.openxmlformats.org/officeDocument/2006'
_NSR = '{%s/relationships}' % _OFF
_NSP = '{http://schemas.openxmlformats.org/package/2006/relationships}'
_BUILTIN_DATE = set(
    list(range(14, 23))
    + list(range(27, 37))
    + list(range(45, 48))
    + list(range(50, 59))
)


def _is_date_format(code):
    code = re.sub(r'"[^"]*"|\\.|\[[^\]]*\]|_.|\*.', '', code)
    return re.search(r'[dmyhs]', code, re.I) is not None


def _split_ref(ref):
    m = re.match(r'([A-Za-z]+)(\d+)$', ref)
    n = 0
    for ch in m.group(1).upper():
        n = n * 26 + ord(ch) - 64
    return n, int(m.group(2))


def _si_text(si):
    if si is None:
        return None
    parts = []
    for node in si:
        if node.tag == _NS + 't':
            parts.append(node.text or '')
        elif node.tag == _NS + 'r':
            parts.extend(t.text or '' for t in node.findall(_NS + 't'))
    return ''.join(parts).replace('x005F_', '')


class XlsxBook(object):

    def __init__(self, path):
        self.path = path
        try:
            self.z = zipfile.ZipFile(path, 'r')
            wb = ET.fromstring(self.z.read('xl/workbook.xml'))
            rels = ET.fromstring(
                self.z.read('xl/_rels/workbook.xml.rels')
            )
        except (
            zipfile.BadZipFile,
            KeyError,
            ET.ParseError,
            OSError,
        ) as e:
            raise AuditError(
                "Cannot open %s as an Excel (.xlsx) workbook (%s)"
                % (os.path.basename(path), e)
            )
        targets = {}
        for r in rels.findall(_NSP + 'Relationship'):
            t = r.get('Target', '')
            targets[r.get('Id')] = (
                t.lstrip('/')
                if t.startswith('/')
                else posixpath.normpath('xl/' + t)
            )
        pr = wb.find(_NS + 'workbookPr')
        self.epoch1904 = pr is not None and pr.get('date1904') in (
            '1',
            'true',
        )
        self.sheets = []
        for s in wb.find(_NS + 'sheets'):
            self.sheets.append(
                (
                    s.get('name'),
                    s.get('state', 'visible') == 'visible',
                    targets.get(s.get(_NSR + 'id')),
                )
            )
        self.sst = []
        if 'xl/sharedStrings.xml' in self.z.namelist():
            for si in ET.fromstring(
                self.z.read('xl/sharedStrings.xml')
            ).findall(_NS + 'si'):
                self.sst.append(_si_text(si))
        self.date_xf = set()
        if 'xl/styles.xml' in self.z.namelist():
            st = ET.fromstring(self.z.read('xl/styles.xml'))
            custom = {}
            nf = st.find(_NS + 'numFmts')
            for n in (nf if nf is not None else []):
                custom[int(n.get('numFmtId'))] = n.get('formatCode', '')
            xfs = st.find(_NS + 'cellXfs')
            for i, xf in enumerate(xfs if xfs is not None else []):
                fid = int(xf.get('numFmtId', 0))
                if fid in custom:
                    if _is_date_format(custom[fid]):
                        self.date_xf.add(i)
                elif fid in _BUILTIN_DATE:
                    self.date_xf.add(i)

    def names(self):
        return [s[0] for s in self.sheets]

    def visible_names(self):
        return [s[0] for s in self.sheets if s[1]]

    def close(self):
        self.z.close()

    def _serial(self, v):
        base = (
            datetime.datetime(1904, 1, 1)
            if self.epoch1904
            else datetime.datetime(1899, 12, 30)
        )
        try:
            whole = int(v)
            return base + datetime.timedelta(
                days=whole, seconds=round((v - whole) * 86400)
            )
        except (OverflowError, ValueError):
            return v

    def rows(self, name, expand_merges=False):
        part = next((s[2] for s in self.sheets if s[0] == name), None)
        if part is None or part not in self.z.namelist():
            return []
        root = ET.fromstring(self.z.read(part))
        sd = root.find(_NS + 'sheetData')
        cells, maxc, maxr, rno = {}, 0, 0, 0
        for row in (sd if sd is not None else []):
            rno = int(row.get('r') or rno + 1)
            cno = 0
            for c in row:
                if c.get('r'):
                    cno = _split_ref(c.get('r'))[0]
                else:
                    cno += 1
                t, v = c.get('t'), c.find(_NS + 'v')
                if t == 'inlineStr':
                    val = _si_text(c.find(_NS + 'is'))
                elif v is None or v.text is None:
                    val = None
                elif t == 's':
                    val = self.sst[int(v.text)]
                elif t in ('str', 'e'):
                    val = v.text
                elif t == 'b':
                    val = bool(int(v.text))
                elif t == 'd':
                    try:
                        val = datetime.datetime.strptime(
                            v.text[:19], '%Y-%m-%dT%H:%M:%S'
                        )
                    except ValueError:
                        val = v.text
                else:
                    try:
                        val = (
                            float(v.text)
                            if ('.' in v.text or 'E' in v.text.upper())
                            else int(v.text)
                        )
                    except ValueError:
                        val = v.text
                if (
                    isinstance(val, (int, float))
                    and int(c.get('s', 0)) in self.date_xf
                ):
                    val = self._serial(val)
                if val is None:
                    continue
                cells.setdefault(rno, {})[cno] = val
                maxc = max(maxc, cno)
                maxr = max(maxr, rno)
        if expand_merges:
            mc = root.find(_NS + 'mergeCells')
            for m in (mc if mc is not None else []):
                ref = m.get('ref', '')
                if ':' not in ref:
                    continue
                a_ref, b_ref = ref.split(':', 1)
                c1, r1 = _split_ref(a_ref)
                c2, r2 = _split_ref(b_ref)
                top_val = cells.get(r1, {}).get(c1)
                if top_val is not None:
                    for rr in range(r1, r2 + 1):
                        for cc in range(c1, c2 + 1):
                            if cc not in cells.get(rr, {}):
                                cells.setdefault(rr, {})[cc] = top_val
                    maxc = max(maxc, c2)
                    maxr = max(maxr, r2)
        return [
            [cells.get(r, {}).get(c) for c in range(1, maxc + 1)]
            for r in range(1, maxr + 1)
        ]


# === IP / port / service parsing ===
MAXIP = 2**32 - 1
IPV4 = r'\d{1,3}(?:\.\d{1,3}){3}'
_FULL_RANGE = re.compile(
    r'(?<![\d.])(%s)\s*(?:-|\u2013|\u2014|\bto\b)\s*(%s)(?![\d.])'
    % (IPV4, IPV4),
    re.I,
)
_SHORT_RANGE = re.compile(
    r'(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})\s*(?:-|\u2013|\u2014|\bto\b)'
    r'\s*(\d{1,3})(?![\d.])',
    re.I,
)
_CIDR_OR_IP = re.compile(
    r'(?<![\d.])(%s)(?:\s*/\s*(\d{1,2})(?![\d.]))?(?![\d.])' % IPV4
)


def clean(v):
    if v is None:
        return ''
    return (
        str(v)
        .replace('_x000D_', '')
        .replace('\xa0', ' ')
        .replace('\r', '')
    )


def ip2i(s):
    parts = s.split('.')
    if len(parts) != 4:
        raise ValueError(s)
    n = 0
    for p in parts:
        v = int(p)
        if v > 255:
            raise ValueError(s)
        n = (n << 8) | v
    return n


def i2ip(i):
    return '%d.%d.%d.%d' % (
        (i >> 24) & 255,
        (i >> 16) & 255,
        (i >> 8) & 255,
        i & 255,
    )


def _ivmerge(iv):
    out = []
    for a, b in sorted(iv):
        if out and a <= out[-1][1] + 1:
            if b > out[-1][1]:
                out[-1] = (out[-1][0], b)
        else:
            out.append((a, b))
    return out


def _subtract(a, b):
    out, j = [], 0
    for s, e in a:
        cur = s
        while j < len(b) and b[j][1] < cur:
            j += 1
        k = j
        while k < len(b) and b[k][0] <= e:
            bs, be = b[k]
            if bs > cur:
                out.append((cur, bs - 1))
            cur = max(cur, be + 1)
            if cur > e:
                break
            k += 1
        if cur <= e:
            out.append((cur, e))
    return out


class IPSet(object):
    __slots__ = ('iv',)

    def __init__(self, iv=()):
        self.iv = _ivmerge(iv)

    @classmethod
    def any(cls):
        return cls([(0, MAXIP)])

    def __bool__(self):
        return bool(self.iv)

    def __or__(self, o):
        return IPSet(self.iv + o.iv)

    union = __or__

    def __sub__(self, o):
        return IPSet(_subtract(self.iv, o.iv))

    def __and__(self, o):
        return IPSet(_subtract(self.iv, _subtract(self.iv, o.iv)))

    def __eq__(self, o):
        return isinstance(o, IPSet) and self.iv == o.iv

    def __hash__(self):
        return hash(tuple(self.iv))

    def count(self):
        return sum(b - a + 1 for a, b in self.iv)

    def is_any(self):
        return self.iv == [(0, MAXIP)]

    def overlaps(self, o):
        return bool(self & o)

    def fmt(self, limit=6):
        if self.is_any():
            return 'ANY'
        parts = [
            i2ip(a) if a == b else '%s-%s' % (i2ip(a), i2ip(b))
            for a, b in self.iv
        ]
        s = ', '.join(parts[:limit])
        return s + (
            ' ...(+%d more)' % (len(parts) - limit)
            if len(parts) > limit
            else ''
        )

    def summary(self, limit=5):
        n = self.count()
        return '%d IP%s: %s' % (
            n,
            '' if n == 1 else 's',
            self.fmt(limit),
        )


_V6_CAND = re.compile(r'(?<![\w:.])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:/\d{1,3})?)(?![\w:])')


def ipv6_tokens(text):
    """IPv6 addresses/networks found in text. IPv6 is not compared yet,
    so callers report these as 'not checked' instead of dropping them."""
    out = []
    for m in _V6_CAND.finditer(clean(text)):
        tok = m.group(1)
        try:
            ipaddress.ip_network(tok, strict=False)
        except ValueError:
            continue
        if ":" in tok and tok not in out:
            out.append(tok)
    return out


def parse_ip_text(text):
    text = clean(text)
    iv = []

    def _full(m):
        try:
            a, b = ip2i(m.group(1)), ip2i(m.group(2))
            iv.append((min(a, b), max(a, b)))
        except ValueError:
            pass
        return ' '

    text = _FULL_RANGE.sub(_full, text)

    def _short(m):
        lo, hi = int(m.group(2)), int(m.group(3))
        if lo < hi <= 255:
            iv.append(
                (
                    ip2i(m.group(1) + m.group(2)),
                    ip2i(m.group(1) + m.group(3)),
                )
            )
            return ' '
        return m.group(0)

    text = _SHORT_RANGE.sub(_short, text)
    for m in _CIDR_OR_IP.finditer(text):
        try:
            if m.group(2):
                bits = int(m.group(2))
                if bits > 32:
                    continue
                base, size = ip2i(m.group(1)), 1 << (
                    32 - int(m.group(2))
                )
                start = base - (base % size)
                iv.append((start, start + size - 1))
            else:
                a = ip2i(m.group(1))
                iv.append((a, a))
        except ValueError:
            continue
    return IPSet(iv)


class PortSet(object):
    __slots__ = ('d',)

    def __init__(self, items=()):
        d = {}
        for proto, lo, hi in items:
            d.setdefault(proto, []).append((lo, hi))
        self.d = dict((p, _ivmerge(v)) for p, v in d.items())

    @classmethod
    def from_dict(cls, d):
        o = cls()
        o.d = dict((p, v) for p, v in d.items() if v)
        return o

    def items(self):
        return [
            (p, a, b) for p, v in sorted(self.d.items()) for a, b in v
        ]

    def __bool__(self):
        return any(self.d.values())

    def __or__(self, o):
        r = dict((p, list(v)) for p, v in self.d.items())
        for p, v in o.d.items():
            r.setdefault(p, []).extend(v)
        return PortSet.from_dict(
            dict((p, _ivmerge(v)) for p, v in r.items())
        )

    def __sub__(self, o):
        return PortSet.from_dict(
            dict(
                (p, _subtract(v, o.d.get(p, [])))
                for p, v in self.d.items()
            )
        )

    def __and__(self, o):
        return PortSet.from_dict(
            dict(
                (p, _subtract(v, _subtract(v, o.d.get(p, []))))
                for p, v in self.d.items()
            )
        )

    def __eq__(self, o):
        return isinstance(o, PortSet) and self.d == o.d

    def __hash__(self):
        return hash(tuple(self.items()))

    def overlaps(self, o):
        return bool(self & o)

    def count(self):
        return sum(b - a + 1 for v in self.d.values() for a, b in v)

    def contains(self, port, proto=None):
        for p, v in self.d.items():
            if (proto and p != proto) or p == 'icmp':
                continue
            if any(a <= port <= b for a, b in v):
                return True
        return False

    def is_everything(self):
        return all(
            self.d.get(p) == [(1, 65535)] for p in ('tcp', 'udp')
        )

    def fmt(self):
        if not self:
            return ''
        if self.is_everything():
            return 'ANY (tcp+udp 1-65535)'
        parts = []
        for proto, v in sorted(self.d.items()):
            if proto == 'icmp':
                parts.append('icmp')
            else:
                parts.append(
                    proto
                    + '/'
                    + ','.join(
                        str(a) if a == b else '%d-%d' % (a, b)
                        for a, b in v
                    )
                )
        return ' '.join(parts)


_PROTO = r'(tcp|udp)'


def _ptype_protos(ptype):
    t = clean(ptype).lower()
    pr = [p for p in ('tcp', 'udp') if p in t]
    if 'icmp' in t:
        pr.append('icmp')
    if ('both' in t or 'all' in t) and not pr:
        pr = ['tcp', 'udp']
    return pr


def parse_rfc_ports(cell, ptype=None):
    protos = _ptype_protos(ptype)
    assumed = not protos
    if assumed:
        protos = ['tcp']
    items, unknown = [], []
    for tok in re.split(
        r'[\n\r,;&|]+|\band\b', clean(cell), flags=re.I
    ):
        tok = tok.strip()
        if not tok or tok.upper() in ('N/A', 'NA', '-', 'NIL'):
            continue
        tl = tok.lower()
        if tl in ('any', 'all'):
            items += [('tcp', 1, 65535), ('udp', 1, 65535)]
            continue
        if tl in ('icmp', 'ping'):
            items.append(('icmp', 0, 0))
            continue
        mp = re.match(r'^[^()]+\(\s*([0-9,\s/\-]+)\s*\)$', tl)
        if mp:
            inner = mp.group(1)
            for sub in re.split(r'[,/\s]+', inner):
                sub = sub.strip()
                if not sub:
                    continue
                rm = re.fullmatch(r'(\d+)\s*-\s*(\d+)', sub)
                if rm:
                    lo, hi = int(rm.group(1)), int(rm.group(2))
                    for p in protos:
                        items.append((p, min(lo, hi), max(lo, hi)))
                elif sub.isdigit():
                    for p in protos:
                        items.append((p, int(sub), int(sub)))
            continue
        if tl in CONFIG.get("named_services", {}):
            for p, lo, hi in CONFIG["named_services"][tl]:
                items.append((p, lo, hi))
            continue
        m = re.fullmatch(
            _PROTO + r'\s*[/:_\- ]\s*(\d+)(?:\s*(?:-|to)\s*(\d+))?', tl
        )
        if m:
            lo = int(m.group(2))
            items.append(
                (m.group(1), lo, int(m.group(3)) if m.group(3) else lo)
            )
            continue
        m = re.fullmatch(
            r'(\d+)(?:\s*(?:-|to)\s*(\d+))?\s*[/:_\- ]?\s*\(?'
            + _PROTO
            + r'\)?',
            tl,
        )
        if m:
            lo = int(m.group(1))
            items.append(
                (m.group(3), lo, int(m.group(2)) if m.group(2) else lo)
            )
            continue
        m = re.fullmatch(r'(\d+)\s*(?:-|\u2013|to)\s*(\d+)', tl)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            for p in protos:
                items.append((p, min(lo, hi), max(lo, hi)))
            continue
        if re.fullmatch(r'\d+', tl):
            for p in protos:
                items.append((p, int(tl), int(tl)))
            continue
        if re.fullmatch(r'\d+(?:\s*[/\s]\s*\d+)+', tl):
            for n in re.split(r'[/\s]+', tl):
                for p in protos:
                    items.append((p, int(n), int(n)))
            continue
        unknown.append(tok)
    items = [
        (p, lo, hi) for p, lo, hi in items if 0 <= lo <= hi <= 65535
    ]
    return PortSet(items), unknown, assumed


class ServiceResult(object):
    def __init__(self):
        self.ports = PortSet()
        self.unresolved = []
        self.low = []
        self.any_service = False
        self.tokens = []


def split_marked(cell):
    out, pending = [], ''
    for line in clean(cell).split('\n'):
        t = line.strip()
        if not t:
            continue
        if t in ('+', '-'):
            pending = t
            continue
        m = re.match(r'^([+-])\s+(.*)$', t)
        if m:
            out.append((m.group(1), m.group(2).strip()))
        else:
            out.append((pending, t))
            pending = ''
    return out


def after_state(cell):
    return [t for m, t in split_marked(cell) if m != '-']


def added_only(cell):
    return [t for m, t in split_marked(cell) if m == '+']


def has_markers(cell):
    return any(m for m, _ in split_marked(cell))


def parse_services(tokens, named=None):
    named = CONFIG["named_services"] if named is None else named
    res = ServiceResult()
    res.tokens = list(tokens)
    items = []
    for t in tokens:
        t = re.sub(r'^[+-]\s*', '', t.strip())
        tl = t.lower().strip()
        if not tl:
            continue
        if tl == 'any':
            res.any_service = True
            items += [('tcp', 1, 65535), ('udp', 1, 65535)]
            continue
        if tl == 'application-default':
            res.unresolved.append(t)
            continue
        if tl in named:
            items += [tuple(x) for x in named[tl]]
            continue
        m = re.fullmatch(
            r'(?:obj_)?(tcp|udp)[_\- /:]*(\d+)(?:-(\d+))?', tl
        )
        if m:
            lo = int(m.group(2))
            items.append(
                (m.group(1), lo, int(m.group(3)) if m.group(3) else lo)
            )
            continue
        m = re.fullmatch(r'(\d+)(?:-(\d+))?[_\- /]*(tcp|udp)', tl)
        if m:
            lo = int(m.group(1))
            items.append(
                (m.group(3), lo, int(m.group(2)) if m.group(2) else lo)
            )
            continue
        if re.fullmatch(r'dm_inline_(?:tcp|udp)_\d+', tl):
            res.unresolved.append(t)
            continue
        m = re.search(r'_(tcp|udp)_(\d+)(?:_\d+)?$', tl)
        if m and int(m.group(2)) <= 65535:
            items.append((m.group(1), int(m.group(2)), int(m.group(2))))
            res.low.append(t)
            continue
        res.unresolved.append(t)
    res.ports = PortSet(
        [(p, lo, hi) for p, lo, hi in items if 0 <= lo <= hi <= 65535]
    )
    return res


class AddrResult(object):
    def __init__(self):
        self.ips = IPSet()
        self.added = IPSet()
        self.marked = False
        self.unresolved = []
        self.any_addr = False


_NAME_WITH_IP = re.compile(
    r'^\w{1,4}_\d{1,3}(?:\.\d{1,3}){3}(?:-\d{1,3}(?:\.\d{1,3}){0,3})?$'
)


def parse_addr_cell(cell):
    res = AddrResult()
    marked = split_marked(cell)
    res.marked = any(m for m, _ in marked)
    full, add = [], []

    def push(marker, ipset):
        if marker == '-':
            return
        full.append(ipset)
        if marker == '+':
            add.append(ipset)

    has_pairs = any(t.endswith(':') for m, t in marked if m != '-')
    i = 0
    while i < len(marked):
        marker, t = marked[i]
        if marker == '-':
            i += 2 if t.endswith(':') else 1
            continue
        if t.endswith(':'):
            if i + 1 < len(marked):
                vm, vt = marked[i + 1]
                if vt.lower() == 'any':
                    res.any_addr = True
                    push(marker or vm, IPSet.any())
                else:
                    s = parse_ip_text(vt)
                    if s:
                        push(marker or vm, s)
                    else:
                        res.unresolved.append(t.rstrip(':'))
                i += 2
            else:
                res.unresolved.append(t.rstrip(':'))
                i += 1
            continue
        if t.lower() == 'any':
            res.any_addr = True
            push(marker, IPSet.any())
        elif (
            not has_pairs
            or _NAME_WITH_IP.match(t)
            or re.fullmatch(
                IPV4 + r'(?:/\d{1,2}|\s*-\s*' + IPV4 + ')?', t
            )
        ):
            s = parse_ip_text(t)
            if s:
                push(marker, s)
            else:
                res.unresolved.append(t)
        else:
            res.unresolved.append(t)
        i += 1
    for attr, sets in (('ips', full), ('added', add)):
        u = IPSet()
        for s in sets:
            u = u | s
        setattr(res, attr, u)
    return res


# === AlgoSec report reader ===
CHANGE_TYPES = ("added", "edited", "removed", "deleted")
TIME_FORMATS = (
    "%b %d, %Y %H:%M:%S",
    "%b %d, %Y %I:%M:%S %p",
    "%b %d, %Y %I:%M %p",
    "%b %d, %Y %H:%M",
    "%d-%b-%Y %H:%M:%S",
    "%d-%b-%Y %I:%M:%S %p",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%dT%H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%d-%m-%Y %H:%M:%S",
    "%d-%m-%Y %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%Y-%m-%d",
    "%d-%m-%Y",
    "%d/%m/%Y",
)


class RawRow(object):
    __slots__ = ("row_no", "values", "section")

    def __init__(self, row_no, values, section="RULES"):
        self.row_no, self.values, self.section = row_no, values, section


class AlgoSecReport(object):
    def __init__(self, path):
        self.path = path
        self.filename = os.path.basename(path)
        self.device = device_from_filename(self.filename)
        self.period = period_from_filename(self.filename)
        self.layout = "UNKNOWN"
        self.headers = []
        self.rows = []
        self.nat_rows = []
        self.declared_total = None
        self.counts = {}
        self.checksum_ok = None
        self.warnings = []

    def col(self, header, nth=0):
        hits = [
            i
            for i, h in enumerate(self.headers)
            if h.strip().lower() == header.strip().lower()
        ]
        return hits[nth] if len(hits) > nth else None


def device_from_filename(filename):
    name = re.sub(r'\.__[0-9a-f]{6,}', '', filename)
    name = re.sub(r'\.xlsx?$', '', name, flags=re.I)
    m = re.search(r'^(.*?)[_ ]*-[_ ]*Changes[_ ]*Summary', name, re.I)
    name = m.group(1) if m else re.split(r'\s+-\s+|_-_', name)[0]
    return name.strip(' _-')


def period_from_filename(filename):
    m = re.search(
        r'([A-Z][a-z]{2})_(\d{1,2})_(\d{4})_-_([A-Z][a-z]{2})_(\d{1,'
        r'2})_(\d{4})',
        filename,
    )
    if not m:
        return None
    try:
        a = datetime.datetime.strptime(
            '%s %s %s' % m.group(1, 2, 3), '%b %d %Y'
        ).date()
        b = datetime.datetime.strptime(
            '%s %s %s' % m.group(4, 5, 6), '%b %d %Y'
        ).date()
        return (a, b)
    except ValueError:
        return None


def parse_time(text):
    if isinstance(text, datetime.datetime):
        return text
    if isinstance(text, datetime.date):
        return datetime.datetime(text.year, text.month, text.day)
    lines = after_state(text)
    t = (lines[0] if lines else clean(text)).strip()
    t = re.sub(r"\s+", " ", t)
    for f in TIME_FORMATS:
        try:
            return datetime.datetime.strptime(t, f)
        except ValueError:
            continue
    return None


def _declared_total(bk):
    if "GENERAL" not in bk.names():
        return None
    rows = bk.rows("GENERAL")
    for r in rows[:30]:
        for i, v in enumerate(r):
            if 'total number of changes' in clean(v).lower():
                for w in r[i + 1 :]:
                    m = re.search(r'\d+', clean(w))
                    if m:
                        return int(m.group(0))
    if len(rows) >= 3 and len(rows[2]) >= 2:
        m = re.search(r'\d+', clean(rows[2][1]))
        if m:
            return int(m.group(0))
    return None


def read_report(path):
    if not os.path.isfile(path):
        raise AuditError("File not found: %s" % path)
    bk = XlsxBook(path)
    try:
        rep = AlgoSecReport(path)
        names = bk.names()
        sheet = next(
            (n for n in names if n.strip().upper() == "RULES"), None
        )
        if sheet is None:
            raise AuditError(
                "%s has no RULES sheet. Sheets found: %s. Is this an"
                " AlgoSec Changes Summary report?"
                % (rep.filename, ", ".join(names))
            )
        rows = bk.rows(sheet)
        hdr = next(
            (
                i
                for i, r in enumerate(rows[:12])
                if r and clean(r[0]).strip().lower() == "change type"
            ),
            None,
        )
        if hdr is None:
            raise AuditError(
                "%s: could not find the header row (a cell A with"
                " 'Change Type') in the first 12 rows of RULES."
                % rep.filename
            )
        headers = [clean(h).strip() for h in rows[hdr]]
        while headers and not headers[-1]:
            headers.pop()
        rep.headers = headers
        hl = [h.lower() for h in headers]
        if "from zone" in hl or "tag" in hl or "hip profile" in hl:
            rep.layout = "PA"
        elif (
            "services & applications" in hl
            or "layer type" in hl
            or "install on" in hl
        ):
            rep.layout = "CP"
        nat = False
        for i in range(hdr + 1, len(rows)):
            r = rows[i]
            a = clean(r[0] if r else None).strip()
            if not a:
                if any(clean(x).strip() for x in r):
                    rep.warnings.append(
                        "row %d has data but an empty Change Type; it"
                        " was kept" % (i + 1)
                    )
                else:
                    continue
            if a.lower().startswith("nat rules"):
                nat = True
                continue
            if a.lower() == "change type":
                continue
            vals = list(r) + [None] * (len(headers) - len(r))
            if nat:
                rep.nat_rows.append(RawRow(i + 1, vals, "NAT"))
            else:
                rep.rows.append(RawRow(i + 1, vals[: len(headers)]))
        rep.declared_total = _declared_total(bk)
        objs = topo = risk = 0
        if "POLICY OBJECTS" in names:
            objs = sum(
                1
                for r in bk.rows("POLICY OBJECTS")
                if r and clean(r[0]).strip().lower() in CHANGE_TYPES
            )
        if "TOPOLOGY" in names:
            topo = sum(
                1
                for r in bk.rows("TOPOLOGY")[1:]
                if r and clean(r[0]).strip()
            )
        if "RISKS" in names:
            risk = sum(
                1
                for r in bk.rows("RISKS")[1:]
                if r and clean(r[0]).strip()
            )
        rep.counts = {
            "rules": len(rep.rows),
            "nat": len(rep.nat_rows),
            "objects": objs,
            "topology": topo,
            "risks": risk,
        }
        computed = (
            len(rep.rows) + len(rep.nat_rows) + objs + topo + risk
        )
        rep.counts["computed_total"] = computed
        if rep.declared_total is not None:
            rep.checksum_ok = computed == rep.declared_total
            if not rep.checksum_ok:
                rep.warnings.append(
                    "GENERAL says %d total changes but the sheets add"
                    " up to %d; some rows may be missing from the"
                    " download" % (rep.declared_total, computed)
                )
        log.info(
            "%s: layout=%s rules=%d nat=%d objects=%d declared=%s"
            " checksum=%s",
            rep.filename,
            rep.layout,
            len(rep.rows),
            len(rep.nat_rows),
            objs,
            rep.declared_total,
            rep.checksum_ok,
        )
        return rep
    finally:
        bk.close()


# === RFC port sheet reader ===
class RfcLine(object):
    def __init__(self):
        self.sr = self.row = None
        self.sheet = self.direction = self.justification = ""
        self.src, self.dst, self.ports = IPSet(), IPSet(), PortSet()
        self.unk_ports, self.unparsed_addr = [], []
        self.ports_assumed_proto = self.continuation = False
        self.src_text = self.dst_text = self.port_text = ""
        self.src_owners, self.dst_owners = [], []
        self.src_apps, self.dst_apps = [], []

    @property
    def bidirectional(self):
        d = self.direction.lower().strip()
        if not d or 'uni' in d:
            return False
        return bool(
            re.search(
                r'\bbi[\s\-_/]*directional|\bbidirectional|\bboth\b|\b'
                r'two[\s\-]?way|<-+>|\bbi\b',
                d,
            )
        )


class RfcSheet(object):
    def __init__(self, number, path):
        self.number, self.path = number, path
        self.filename = os.path.basename(path)
        self.sheet = self.requirement = self.change_kind = (
            self.requested_for
        ) = ""
        self.lines, self.warnings = [], []
        self.date = None


def find_rfc_number(path, regex=r'RFC[._\- ]*(\d{9})'):
    m = re.search(regex, os.path.basename(path), re.I)
    return m.group(1) if m else None


def _txt(v):
    return re.sub(r'\s+', ' ', clean(v)).strip()


def split_owners(v):
    out = []
    for part in re.split(r'[\r\n]+', clean(v)):
        t = re.sub(r'\s+', ' ', part).strip()
        if t:
            out.append(t)
    return out


def _parse_date(v):
    if isinstance(v, datetime.datetime):
        return v.date()
    if isinstance(v, datetime.date):
        return v
    t = _txt(v)
    for f in (
        "%d.%m.%Y",
        "%d/%m/%Y",
        "%d-%m-%Y",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%d %b %Y",
        "%b %d, %Y",
    ):
        try:
            return datetime.datetime.strptime(t, f).date()
        except ValueError:
            continue
    return None


_SRC_GROUP = ('source', 'src', 'source details', 'source server',
              'source server details', 'source side', 'source system',
              'source ip details', 'source details ip')
_DST_GROUP = ('destination', 'dest', 'dst', 'destination details',
              'destination server', 'destination server details',
              'destination side', 'destination system', 'target',
              'dest details', 'destination ip details')
_PT_WORDS = ('port type', 'pot type', 'pot_type', 'port_type', 'protocol',
             'proto', 'tcp udp', 'tcp/udp')


def _hnorm(v):
    """Header text, lower-case, punctuation folded to spaces."""
    t = _txt(v).lower()
    t = re.sub(r'[^a-z0-9/+&]+', ' ', t)
    return re.sub(r'\s+', ' ', t).strip()


def _is_group(t, words):
    return t in words


def _ip_col(t):
    if re.search(r'\b(owner|nat|nated|natted|name|zone|application|'
                 r'hostname|host name|vip|translated)\b', t):
        return 0
    if 'ip address' in t or 'ip addr' in t:
        return 3
    if re.search(r'\bip\b', t) or 'ip/subnet' in t:
        return 2
    if 'subnet' in t or 'network address' in t:
        return 1
    return 0


def _best(sub, lo, hi, score):
    best, bi = 0, None
    for i, t in sorted(sub.items()):
        if lo <= i < hi:
            s = score(t)
            if s > best:
                best, bi = s, i
    return bi


def _port_col(t):
    if 'type' in t or 'source port' in t or 'src port' in t:
        return 0
    if 'destination port' in t or 'dest port' in t or 'dst port' in t:
        return 3
    if re.search(r'\bports?\b', t) or 'port no' in t:
        return 2
    if t in ('service', 'services', 'service port'):
        return 1
    return 0


def _first(items, pred):
    return next((i for i, t in sorted(items) if pred(t)), None)


def _layout_dict(group_row, data_start, txt, sub, sc, dc, src_ip, dst_ip,
                 dport, mode):
    both = list(txt.items()) + list(sub.items())
    ptype = _first(txt.items(), lambda t: any(k in t for k in _PT_WORDS))
    if ptype is None:
        ptype = _first(sub.items(), lambda t: any(k in t for k in _PT_WORDS))

    def side(word, lo, hi):
        return next((i for i, t in sorted(sub.items())
                     if word in t and lo <= i < hi), None)

    big = 10 ** 6
    direction = _first(both, lambda t: t.startswith('direction')
                       or ('direction' in t and 'flow' in t))
    just = _first(both, lambda t: t.startswith('justification')
                  or t.startswith('business justification'))
    sr = _first(both, lambda t: t.startswith(('sr', 's no', 'serial', 'sl no',
                                              'sno', 'line no', 'item no')))
    return dict(
        group_row=group_row,
        data_start=data_start,
        mode=mode,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dport=dport,
        ptype=ptype,
        direction=direction,
        just=just,
        sr=sr,
        src_owner=side('owner', sc, dc),
        dst_owner=side('owner', dc, big),
        src_app=side('application', sc, dc),
        dst_app=side('application', dc, big),
    )


def _row_text(row):
    return dict(
        (i, _hnorm(v)) for i, v in enumerate(row) if v is not None and _hnorm(v)
    )


def _find_layout(rows, max_scan=60):
    """Find the Source / Destination table.

    Handles: merged group headers ("Source" spanning several columns),
    header synonyms (Src, Source Details, Dest, Target ...), sub-headers
    on 1 or 2 rows below the group row, and single-row headers such as
    "Source IP | Destination IP | Port".  `rows` should have merged cells
    filled in (XlsxBook.rows(..., expand_merges=True)).
    """
    n = min(max_scan, len(rows))
    for ri in range(n):
        txt = _row_text(rows[ri])
        src = [i for i, t in txt.items() if _is_group(t, _SRC_GROUP)]
        dst = [i for i, t in txt.items() if _is_group(t, _DST_GROUP)]
        if src and dst and min(src) < min(dst):
            sc, dc = min(src), min(dst)
            for depth in (1, 2):
                if ri + depth >= len(rows):
                    break
                sub = {}
                for k in range(1, depth + 1):
                    for i, t in _row_text(rows[ri + k]).items():
                        if t in (_SRC_GROUP + _DST_GROUP):
                            continue
                        sub[i] = (sub[i] + ' ' + t) if i in sub else t
                src_ip = _best(sub, sc, dc, _ip_col)
                dst_ip = _best(sub, dc, 10 ** 6, _ip_col)
                dport = _best(sub, dc, 10 ** 6, _port_col)
                if dport is None:
                    # port column sometimes sits under neither group
                    dport = _best(dict((i, t) for i, t in txt.items()
                                       if i >= dc), dc, 10 ** 6, _port_col)
                if src_ip is not None and dst_ip is not None and dport is not None:
                    return _layout_dict(ri, ri + depth + 1, txt, sub, sc, dc,
                                        src_ip, dst_ip, dport,
                                        "grouped-%d" % depth)
        # single-row header: "Source IP" ... "Destination IP" ... "Port"
        sip = _first(txt.items(), lambda t: (t.startswith(('source', 'src'))
                                             and _ip_col(t) >= 2))
        dip = _first(txt.items(), lambda t: (t.startswith(('destination', 'dest', 'dst', 'target'))
                                             and _ip_col(t) >= 2))
        if sip is not None and dip is not None and sip < dip:
            dport = _best(txt, dip, 10 ** 6, _port_col)
            if dport is None:
                dport = _best(txt, 0, 10 ** 6, _port_col)
            if dport is not None:
                return _layout_dict(ri, ri + 1, txt, txt, sip, dip, sip, dip,
                                    dport, "single-row")
    return None


def _col_index(ref):
    """'C' -> 2, 3 -> 2 (1-based numbers allowed), None -> None."""
    if ref is None or ref == "":
        return None
    if isinstance(ref, int):
        return ref - 1
    s = str(ref).strip().upper()
    if s.isdigit():
        return int(s) - 1
    n = 0
    for ch in s:
        if not ('A' <= ch <= 'Z'):
            raise AuditError("Template column %r is not a column letter" % ref)
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def _template_layout(tpl):
    cols = tpl.get("columns") or {}
    for need in ("src_ip", "dst_ip", "port"):
        if not cols.get(need):
            raise AuditError(
                "RFC template %r needs columns.%s" % (tpl.get("name", "?"), need)
            )
    hdr = int(tpl.get("header_row", 1))
    lay = dict(
        group_row=max(hdr - 1, 0),
        data_start=int(tpl.get("data_start", hdr + 1)) - 1,
        mode="template:%s" % tpl.get("name", "unnamed"),
        src_ip=_col_index(cols["src_ip"]),
        dst_ip=_col_index(cols["dst_ip"]),
        dport=_col_index(cols["port"]),
        ptype=_col_index(cols.get("ptype")),
        direction=_col_index(cols.get("direction")),
        just=_col_index(cols.get("justification")),
        sr=_col_index(cols.get("sr")),
        src_owner=_col_index(cols.get("src_owner")),
        dst_owner=_col_index(cols.get("dst_owner")),
        src_app=_col_index(cols.get("src_app")),
        dst_app=_col_index(cols.get("dst_app")),
    )
    return lay


def _templates_for(path, rfc_cfg):
    out = []
    for tpl in (rfc_cfg or {}).get("templates") or []:
        fre = tpl.get("file_regex")
        if fre and not re.search(fre, os.path.basename(path), re.I):
            continue
        out.append(tpl)
    return out


def _first_val(r, i):
    return next(
        (
            r[j]
            for j in range(i + 1, len(r))
            if r[j] is not None and _txt(r[j])
        ),
        None,
    )


def _meta(rows, sheet, group_row):
    for r in rows[:group_row]:
        for i, t in [
            (i, _txt(v))
            for i, v in enumerate(r)
            if v is not None and _txt(v)
        ]:
            tl, val = t.lower(), _first_val(r, i)
            if val is None:
                continue
            if tl == 'date' and sheet.date is None:
                sheet.date = _parse_date(val)
            elif tl.startswith('requirement type'):
                sheet.requirement = _txt(val)
            elif tl.startswith('addition/deletion') or tl.startswith(
                'addition / deletion'
            ):
                sheet.change_kind = _txt(val)
    for r in rows:
        for i, v in enumerate(r):
            if v is not None and _txt(v).lower().startswith(
                'requested for'
            ):
                val = _first_val(r, i)
                if val is not None:
                    sheet.requested_for = _txt(val)


def _sheet_lines(rows, layout, wsname, sheet):
    def cell(r, c):
        return r[c] if c is not None and c < len(r) else None

    def sr_of(r):
        sr_val = cell(r, layout['sr'])
        if isinstance(sr_val, bool):
            return None
        if isinstance(sr_val, (int, float)):
            return int(float(sr_val))
        if isinstance(sr_val, str):
            m = re.match(r'^\s*(\d+)(?:\s*[.)+].*)?\s*$', sr_val.strip())
            if m:
                return int(m.group(1))
        return None

    start = layout['data_start']
    auto = not any(sr_of(rows[ri]) is not None for ri in range(start, len(rows)))
    if auto:
        sheet.warnings.append(
            "Sheet %r: no Sr. No. values found, rows numbered by position"
            % wsname
        )
    lines, last_sr, auto_n = [], None, 0
    for ri in range(start, len(rows)):
        r = rows[ri]
        sr_num = sr_of(r)
        src_text, dst_text = clean(cell(r, layout['src_ip'])), clean(
            cell(r, layout['dst_ip'])
        )
        port_text = clean(cell(r, layout['dport']))
        src, dst = parse_ip_text(src_text), parse_ip_text(dst_text)
        ports, unk, assumed = parse_rfc_ports(
            port_text, cell(r, layout['ptype'])
        )
        has_data = bool(src or dst or ports)
        if auto:
            if not has_data:
                continue
            auto_n += 1
            sr, cont = auto_n, False
        elif sr_num is None:
            if not has_data:
                continue
            if last_sr is None:
                sheet.warnings.append(
                    "Sheet %r row %d: has IP/port data before the first"
                    " Sr. No.; read as Sr 0" % (wsname, ri + 1)
                )
                last_sr = 0
            sr, cont = last_sr, True
        else:
            sr, cont = sr_num, False
            last_sr = sr
        ln = RfcLine()
        ln.sr, ln.row, ln.sheet, ln.continuation = sr, ri + 1, wsname, cont
        (
            ln.src,
            ln.dst,
            ln.ports,
            ln.unk_ports,
            ln.ports_assumed_proto,
        ) = (src, dst, ports, unk, assumed)
        ln.src_text, ln.dst_text, ln.port_text = src_text, dst_text, port_text
        ln.direction = _txt(cell(r, layout['direction']))
        ln.justification = _txt(cell(r, layout['just']))
        ln.src_owners = split_owners(cell(r, layout['src_owner']))
        ln.dst_owners = split_owners(cell(r, layout['dst_owner']))
        ln.src_apps = split_owners(cell(r, layout.get('src_app')))
        ln.dst_apps = split_owners(cell(r, layout.get('dst_app')))
        for side, text, ips in (
            ("source", src_text, src),
            ("destination", dst_text, dst),
        ):
            v6 = ipv6_tokens(text)
            if v6:
                sheet.warnings.append(
                    "Sr %s: IPv6 %s address(es) not checked: %s"
                    % (sr, side, ", ".join(v6[:5]))
                )
            if not ips:
                ln.unparsed_addr.append(
                    "%s: %r" % (side, _txt(text)[:60])
                )
        lines.append(ln)
    return lines


_SKIP_SHEETS = r'(?i)(sample|example|instruction|guideline|read ?me|\bhelp\b|legend|drop ?down)'


def read_rfc_sheet(path, number=None, regex=r'RFC[._\- ]*(\d{9})', rfc_cfg=None):
    rfc_cfg = rfc_cfg or {}
    number = number or find_rfc_number(path, regex)
    if not number:
        raise AuditError(
            "No RFC number in the file name %s (expected something like"
            " RFC_255862839.xlsx)" % os.path.basename(path)
        )
    read_all = rfc_cfg.get("read_all_sheets", True)
    skip_re = rfc_cfg.get("skip_sheet_regex", _SKIP_SHEETS)
    max_scan = int(rfc_cfg.get("header_scan_rows", 60))
    templates = _templates_for(path, rfc_cfg)
    bk = XlsxBook(path)
    found, skipped, seen_headers = [], [], []
    try:
        names = bk.visible_names()
        for name in names:
            raw = bk.rows(name)
            exp = bk.rows(name, expand_merges=True)
            lay = None
            for tpl in templates:
                sre = tpl.get("sheet")
                if sre and not re.search(sre, name, re.I):
                    continue
                lay = _template_layout(tpl)
                break
            is_skip = False
            if lay is None:
                is_skip = bool(skip_re and re.search(skip_re, name))
                lay = _find_layout(exp, max_scan)
            if lay is None:
                hdrs = [
                    _txt(v) for r in exp[:max_scan] for v in r
                    if isinstance(v, str) and _txt(v) and len(_txt(v)) < 40
                ][:12]
                if hdrs:
                    seen_headers.append("%s: %s" % (name, " | ".join(hdrs)))
                continue
            rows = raw[: lay['data_start']] + exp[lay['data_start']:]
            (skipped if is_skip else found).append((name, lay, rows))
            if found and not read_all:
                break
    finally:
        bk.close()
    if not found and skipped:
        found = skipped[:1]
    sk_names = [f[0] for f in skipped if f not in found]
    if not found:
        raise AuditError(
            "%s: could not find the Source / Destination table (a row"
            " with 'Source' and 'Destination', followed by 'Server IP"
            " Address' and 'Destination Port' headers, or one header row"
            " with 'Source IP', 'Destination IP' and 'Port'). Add an"
            " rfc.templates entry in the config to map the columns by"
            " hand.%s"
            % (
                os.path.basename(path),
                (" Header text seen: " + " || ".join(seen_headers[:2]))
                if seen_headers else "",
            )
        )
    sheet = RfcSheet(number, path)
    sheet.sheet = found[0][0]
    sheet.sheets = [f[0] for f in found]
    sheet.layouts = [(f[0], f[1]['mode']) for f in found]
    _meta(found[0][2], sheet, found[0][1]['group_row'])
    if all(f[1]['src_owner'] is None and f[1]['dst_owner'] is None for f in found):
        sheet.warnings.append(
            "No Source Owner / Dest. Server Owner column found, so"
            " Asset Owner cannot be read from this sheet."
        )
    for wsname, lay, rows in found:
        sheet.lines.extend(_sheet_lines(rows, lay, wsname, sheet))
    if sk_names:
        sheet.warnings.append(
            "Sheet(s) %s look like sample/instruction sheets and were not"
            " read (rfc.skip_sheet_regex)" % ", ".join(repr(n) for n in sk_names)
        )
    if len(found) > 1:
        sheet.warnings.append(
            "Port table read from %d sheets: %s"
            % (len(found), ", ".join(repr(f[0]) for f in found))
        )
    if not sheet.lines:
        raise AuditError(
            "%s: the Source/Destination table was found but it has no"
            " rows with IP or port data." % os.path.basename(path)
        )
    for ln in sheet.lines:
        if ln.unk_ports:
            sheet.warnings.append(
                "Sr %s: port text not understood: %s"
                % (ln.sr, ", ".join(ln.unk_ports))
            )
        if ln.unparsed_addr:
            sheet.warnings.append(
                "Sr %s: no IP address read from %s"
                % (ln.sr, "; ".join(ln.unparsed_addr))
            )
        if ln.ports_assumed_proto and ln.ports:
            sheet.warnings.append(
                "Sr %s: Port Type is blank or unclear, TCP assumed"
                % ln.sr
            )
    log.info(
        "RFC%s: %s sheets=%r lines=%d layout=%s",
        number,
        sheet.filename,
        sheet.sheets,
        len(sheet.lines),
        ",".join(m for _, m in sheet.layouts),
    )
    return sheet


def _is_rfc_excel_file(path, regex=r'RFC[._\- ]*(\d{9})'):
    bn = os.path.basename(path)
    if bn.startswith('~$') or not os.path.isfile(path):
        return False
    low = bn.lower()
    if low.endswith(('.xlsx', '.xlsm')):
        return True
    if '.' not in bn and re.search(regex, bn, re.I):
        try:
            return zipfile.is_zipfile(path)
        except OSError:
            return False
    return False


def load_rfc_folder(folder, regex=r'RFC[._\- ]*(\d{9})', rfc_cfg=None):
    if not os.path.isdir(folder):
        raise AuditError("RFC folder not found: %s" % folder)
    sheets, problems = {}, []
    candidates = []
    for n in sorted(os.listdir(folder)):
        full = os.path.join(folder, n)
        if os.path.isdir(full):
            sub_num = find_rfc_number(n, regex)
            if sub_num:
                for sn in sorted(os.listdir(full)):
                    sfull = os.path.join(full, sn)
                    if _is_rfc_excel_file(sfull, regex):
                        candidates.append((sfull, sub_num))
            continue
        if n.lower().endswith('.xls'):
            problems.append(
                (
                    n,
                    (
                        "Old .xls format is not supported. Open it in"
                        " Excel and Save As .xlsx."
                    ),
                )
            )
            continue
        if _is_rfc_excel_file(full, regex):
            candidates.append((full, None))
    for sh_path, fallback_num in candidates:
        n = os.path.basename(sh_path)
        try:
            sh = read_rfc_sheet(
                sh_path, number=fallback_num, regex=regex, rfc_cfg=rfc_cfg
            )
        except AuditError as e:
            problems.append((n, str(e)))
            log.warning("RFC file skipped: %s", e)
            continue
        if not hasattr(sh, "all_paths"):
            sh.all_paths = [sh_path]
        if sh.number in sheets:
            prev = sheets[sh.number]
            if not hasattr(prev, "all_paths"):
                prev.all_paths = [os.path.join(folder, prev.filename)]
            prev.all_paths.append(sh_path)
            prev.lines.extend(sh.lines)
            prev.warnings.extend(sh.warnings)
            log.info(
                "Merged %s into RFC%s (total %d line(s) across %d file(s))",
                sh.filename,
                sh.number,
                len(prev.lines),
                len(prev.all_paths),
            )
        else:
            sheets[sh.number] = sh
    return sheets, problems


# === SMAX export (offline Excel/CSV) ===
SMAX_FIELDS = ("title", "rfc_owner", "asset_owner", "application", "expiry")
SMAX_LABELS = {
    "title": "Title",
    "rfc_owner": "RFC Owner",
    "asset_owner": "Asset Owner",
    "application": "Application",
    "expiry": "Expiry",
}


class SmaxData(object):
    def __init__(self):
        self.records = {}
        self.problems = []

    def lookup(self, chain):
        for n in chain:
            if n in self.records:
                return self.records[n]
        return None


def _smax_rows(path):
    if path.lower().endswith(".csv"):
        for enc in ("utf-8-sig", "cp1252"):
            try:
                with open(path, "r", encoding=enc, newline="") as f:
                    sample = f.read(4096)
                    f.seek(0)
                    try:
                        dialect = csv.Sniffer().sniff(
                            sample, delimiters=",;\t|"
                        )
                    except csv.Error:
                        dialect = csv.excel
                    return [list(r) for r in csv.reader(f, dialect)]
            except UnicodeDecodeError:
                continue
        raise AuditError(
            "%s: cannot decode the CSV file (tried UTF-8 and"
            " Windows-1252)" % os.path.basename(path)
        )
    bk = XlsxBook(path)
    try:
        for name in bk.visible_names():
            rows = bk.rows(name)
            if rows:
                return rows
    finally:
        bk.close()
    return []


def _col_of(cells, names):
    for n in [x.strip().lower() for x in names]:
        if n in cells:
            return cells.index(n)
    return None


def read_smax_file(path, cfg, data):
    digits = int(cfg["rfc"]["number_digits"])
    al = cfg["smax"]["columns"]
    base = os.path.basename(path)
    rows = _smax_rows(path)
    if not rows:
        raise AuditError("%s is empty" % base)
    want = set(a.strip().lower() for a in al["number"])
    hi = cells = None
    for i, r in enumerate(rows[:25]):
        cl = [clean(c).strip().lower() for c in r]
        if any(c in want for c in cl):
            hi, cells = i, cl
            break
    if hi is None:
        raise AuditError(
            "%s: no header row with an RFC number column. Expected one"
            " of: %s. Add your SMAX column name to smax.columns.number"
            " in the config." % (base, ", ".join(al["number"]))
        )
    ncol = _col_of(cells, al["number"])
    fcols = dict((f, _col_of(cells, al[f])) for f in SMAX_FIELDS)
    fcols = dict((f, c) for f, c in fcols.items() if c is not None)
    missing = [SMAX_LABELS[f] for f in SMAX_FIELDS if f not in fcols]
    if missing:
        data.problems.append(
            (
                base,
                "No column found for %s. Those stay blank. Add the SMAX"
                " column name(s) to smax.columns in the config."
                % ", ".join(missing),
            )
        )
    rx = re.compile(r'(?<!\d)(\d{%d})(?!\d)' % digits)
    n = 0
    for r in rows[hi + 1 :]:
        key = rx.search(clean(r[ncol] if ncol < len(r) else None))
        if not key:
            continue
        rec = data.records.setdefault(
            key.group(1), dict((f, "") for f in SMAX_FIELDS)
        )
        for f, c in fcols.items():
            raw_val = r[c] if c < len(r) else None
            if f == "expiry" and isinstance(
                raw_val, (datetime.datetime, datetime.date)
            ):
                v = (
                    raw_val.date()
                    if isinstance(raw_val, datetime.datetime)
                    else raw_val
                )
            else:
                v = re.sub(r'\s+', ' ', clean(raw_val)).strip()
            if v and not rec[f]:
                rec[f] = v
        n += 1
    log.info("SMAX %s: %d record(s)", base, n)


def load_smax(path, cfg):
    data = SmaxData()
    if not path:
        return data
    if os.path.isdir(path):
        files = [
            os.path.join(path, f)
            for f in sorted(os.listdir(path))
            if f.lower().endswith((".xlsx", ".xlsm", ".csv"))
            and not f.startswith("~$")
        ]
    elif os.path.isfile(path):
        files = [path]
    else:
        raise AuditError("SMAX export not found: %s" % path)
    if not files:
        raise AuditError("No .xlsx or .csv file found in %s" % path)
    for p in files:
        try:
            read_smax_file(p, cfg, data)
        except AuditError as e:
            data.problems.append((os.path.basename(p), str(e)))
            log.warning("SMAX file skipped: %s", e)
    return data


# === rule model ===
DENY_WORDS = ("drop", "deny", "reset", "reject", "block")


class Rule(object):

    def __init__(self):
        self.uid = self.tab_row = self.file_row = self.name_suffix = (
            self.time
        ) = self.enabled = None
        self.tab = self.file = self.layout = self.change_type = (
            self.name
        ) = self.time_text = ""
        self.action = self.description = self.ha_note = ""
        self.origin = "primary"
        self.chain, self.desc_rfcs = [], []
        self.rfc_source = "name"
        self.src, self.dst, self.src_added, self.dst_added = (
            IPSet(),
            IPSet(),
            IPSet(),
            IPSet(),
        )
        self.src_unresolved, self.dst_unresolved = [], []
        self.ports, self.ports_added = PortSet(), PortSet()
        self.svc_tokens, self.svc_unresolved, self.svc_low = [], [], []
        self.any_service = False
        self.edited_markers = {"src": False, "dst": False, "svc": False}
        self.zones = ("", "")
        self.values = []
        self.cons = None

    @property
    def removed(self):
        return self.change_type.lower() in ("removed", "deleted")

    @property
    def edited(self):
        return self.change_type.lower() == "edited"

    @property
    def is_deny(self):
        return any(
            self.action.lower().startswith(w) for w in DENY_WORDS
        )


def _first_line(cell):
    lines = after_state(cell)
    return lines[0].strip() if lines else ""


def role_columns(headers, cfg):
    cols, low = {}, [h.strip().lower() for h in headers]
    for role, aliases in cfg["column_aliases"].items():
        for a in aliases:
            if a.strip().lower() in low:
                cols[role] = low.index(a.strip().lower())
                break
    return cols


def build_rule(
    values, cols, tab, layout, cfg, file, file_row, origin="primary"
):
    r = Rule()
    r.tab, r.layout, r.file, r.file_row, r.origin, r.values = (
        tab,
        layout,
        file,
        file_row,
        origin,
        values,
    )

    def val(role):
        c = cols.get(role)
        return values[c] if c is not None and c < len(values) else None

    r.change_type = clean(val("change_type")).strip()
    r.name = " ".join(after_state(val("name")))
    r.time_text = clean(val("time")).strip()
    r.time = parse_time(val("time"))
    digits = int(cfg["rfc"]["number_digits"])
    seen = []
    for n in re.findall(r'(?<!\d)(\d{%d})(?!\d)' % digits, r.name):
        if n not in seen:
            seen.append(n)
    r.chain = seen
    matches = list(
        re.finditer(
            r'RFC[._\- ]*(\d{%d})(?:[._\-](\d{1,2}))?(?!\d)' % digits, r.name, re.I
        )
    )
    m = matches[-1] if matches else None
    r.name_suffix = int(m.group(2)) if m and m.group(2) else None
    r.description = " ".join(after_state(val("description")))
    for n in re.findall(
        r'RFC[._\- ]*(\d{%d})(?!\d)' % digits, r.description, re.I
    ):
        if n not in r.desc_rfcs:
            r.desc_rfcs.append(n)
    if not r.chain:
        if r.desc_rfcs and cfg["rfc"].get(
            "use_description_when_name_has_none", True
        ):
            r.chain = list(r.desc_rfcs[-1:] if cfg["policy"].get("multi_rfc", "last") == "last" else r.desc_rfcs[:1])
            r.rfc_source = "description"
        else:
            r.rfc_source = None
    s, d = parse_addr_cell(val("source")), parse_addr_cell(
        val("destination")
    )
    r.src, r.dst, r.src_added, r.dst_added = (
        s.ips,
        d.ips,
        s.added,
        d.added,
    )
    r.src_unresolved, r.dst_unresolved = s.unresolved, d.unresolved
    for side, cell in (("source", val("source")), ("destination", val("destination"))):
        lst = r.src_unresolved if side == "source" else r.dst_unresolved
        for tok in ipv6_tokens(" ".join(after_state(cell))):
            label = "%s (IPv6 - not checked)" % tok
            lst[:] = [x for x in lst if x != tok and x.rstrip(":") != tok]
            if label not in lst:
                lst.append(label)
    r.edited_markers["src"], r.edited_markers["dst"] = (
        s.marked,
        d.marked,
    )
    svc_cell = val("service")
    toks = after_state(svc_cell)
    sv = parse_services(toks, cfg.get("named_services"))
    (
        r.ports,
        r.svc_unresolved,
        r.svc_low,
        r.any_service,
        r.svc_tokens,
    ) = (sv.ports, sv.unresolved, sv.low, sv.any_service, toks)
    r.edited_markers["svc"] = has_markers(svc_cell)
    r.ports_added = parse_services(
        added_only(svc_cell), cfg.get("named_services")
    ).ports
    r.action = _first_line(val("action")).strip()
    r.zones = (
        _first_line(val("from_zone")).lower(),
        _first_line(val("to_zone")).lower(),
    )
    en = _first_line(val("enable")).lower()
    r.enabled = (
        None
        if not en
        else en.startswith(("enable", "yes", "true", "on"))
    )
    return r


def _file_custody(path, role="Input"):
    info = {
        "role": role,
        "name": os.path.basename(path),
        "path": path,
        "sha256": "",
        "size_bytes": 0,
        "mtime": "",
    }
    try:
        st = os.stat(path)
        info["size_bytes"] = st.st_size
        info["mtime"] = datetime.datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        info["sha256"] = h.hexdigest()
    except OSError:
        pass
    return info


def _config_hash(cfg):
    raw = json.dumps(cfg, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


class AuditContext(object):

    def __init__(self, cfg):
        self.cfg = cfg
        self.report_date = datetime.date.today()
        self.run_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.operator = cfg.get("prepared_by") or default_operator()
        self.config_hash = _config_hash(cfg)
        self.reports, self.tabs, self.rules = [], [], []
        self.verdicts, self.sheets, self.tab_headers = {}, {}, {}
        (
            self.sheet_problems,
            self.rfc_results,
            self.duplicates,
            self.unexpected,
            self.warnings,
        ) = ([], [], [], [], [])
        self.smax = None
        self.owners = {}
        self.apps = {}
        self.status = ""
        self.job_history = []
        self.input_custody = []
        self.output_custody = []
        self.coverage_summary = (0, 0, [])
        self.report_windows = []

    def warn(self, msg, sev="WARN"):
        self.warnings.append((sev, msg))


# === consolidation (tabs, HA rule) ===
class ConsRow(object):
    def __init__(self, report, raw, values, origin, ha_note=""):
        (
            self.report,
            self.raw,
            self.values,
            self.origin,
            self.ha_note,
        ) = (report, raw, values, origin, ha_note)


class TabData(object):
    def __init__(self, name, layout, ha=False):
        self.name, self.layout, self.ha = name, layout, ha
        self.headers, self.rows, self.reports, self.warnings = (
            [],
            [],
            [],
            [],
        )
        self.ha_stats = {
            "mirrors_dropped": 0,
            "kept_differs": 0,
            "kept_only_partner": 0,
        }


def _norm(v):
    return tuple(x.strip() for x in clean(v).split("\n") if x.strip())


def _signature(report, raw, cols):
    sig = []
    for h in cols:
        c = report.col(h)
        sig.append(
            _norm(raw.values[c])
            if c is not None and c < len(raw.values)
            else ()
        )
    return tuple(sig)


def _safe_tab_name(base, used):
    name = re.sub(r'[\[\]:*?/\\]', '_', base)[:31] or "Report"
    n, cand = 2, name
    while cand in used:
        suffix = "_%d" % n
        cand = name[: 31 - len(suffix)] + suffix
        n += 1
    return cand


def build_tabs(reports, cfg):
    placed = dict((t["name"], []) for t in cfg["tabs"])
    unmatched = []
    for rep in reports:
        hit = None
        for t in cfg["tabs"]:
            for i, pat in enumerate(t["patterns"]):
                if pattern_matches(pat, rep.device):
                    hit = (t, i)
                    break
            if hit:
                break
        if hit:
            placed[hit[0]["name"]].append((hit[1], rep))
        else:
            unmatched.append(rep)
    tabs, used = [], set(t["name"] for t in cfg["tabs"])
    for t in cfg["tabs"]:
        items = sorted(placed[t["name"]], key=lambda x: x[0])
        if not items and not cfg.get("create_empty_tabs", True):
            continue
        td = TabData(t["name"], t["layout"], t.get("ha", False))
        tabs.append(td)
        if not items:
            continue
        primary = items[0][1]
        td.headers = list(primary.headers)
        for idx, rep in items:
            td.reports.append(rep)
            if rep.layout not in ("UNKNOWN", t["layout"]):
                td.warnings.append(
                    "%s looks like a %s report but tab %s is configured"
                    " as %s"
                    % (rep.filename, rep.layout, t["name"], t["layout"])
                )
            _add_rows(
                td,
                rep,
                primary,
                idx,
                cfg["ha_content_columns"].get(t["layout"], []),
            )
        log.info(
            "tab %s: %d rows from %d file(s) %s",
            td.name,
            len(td.rows),
            len(td.reports),
            td.ha_stats,
        )
    for rep in unmatched:
        name = _safe_tab_name(rep.device, used)
        used.add(name)
        td = TabData(
            name,
            rep.layout if rep.layout in ("PA", "CP") else "PA",
            False,
        )
        td.headers = list(rep.headers)
        td.reports.append(rep)
        td.warnings.append(
            "No tab pattern in the config matches %s (device %r). Its"
            " rows are in tab %s so nothing is lost; add a pattern to"
            " map it." % (rep.filename, rep.device, name)
        )
        _add_rows(td, rep, rep, 0, [])
        tabs.append(td)
    return tabs


def _column_map(rep, headers):
    seen, mapping = {}, {}
    for j, h in enumerate(rep.headers):
        k = h.strip().lower()
        n = seen.get(k, 0)
        seen[k] = n + 1
        pos = [
            i for i, th in enumerate(headers) if th.strip().lower() == k
        ]
        if len(pos) > n:
            mapping[j] = pos[n]
    return mapping


def _add_rows(td, rep, primary, pattern_index, content_cols):
    is_partner = td.ha and (rep is not primary)
    mapping = None if rep is primary else _column_map(rep, td.headers)
    if mapping is not None:
        dropped = [
            h
            for j, h in enumerate(rep.headers)
            if j not in mapping and h
        ]
        if dropped:
            td.warnings.append(
                "%s has column(s) not in the tab header: %s (their"
                " values were left out)"
                % (rep.filename, ", ".join(dropped))
            )
    primary_sigs = {}
    if is_partner:
        for pr in td.rows:
            if pr.origin == "primary":
                name = _norm(
                    pr.values[td.headers.index("Name")]
                    if "Name" in td.headers
                    else ""
                )
                primary_sigs.setdefault(name, set()).add(
                    _signature(pr.report, pr.raw, content_cols)
                )
    for raw in rep.rows:
        if mapping is None:
            values = list(raw.values)
        else:
            values = [None] * len(td.headers)
            for j, pos in mapping.items():
                if j < len(raw.values):
                    values[pos] = raw.values[j]
        origin, note = "primary", ""
        if is_partner:
            name_c = rep.col("Name")
            name = (
                _norm(raw.values[name_c]) if name_c is not None else ()
            )
            sig = _signature(rep, raw, content_cols)
            if name in primary_sigs:
                if sig in primary_sigs[name]:
                    td.ha_stats["mirrors_dropped"] += 1
                    continue
                td.ha_stats["kept_differs"] += 1
                note = (
                    "Partner firewall %s: same rule name as the primary"
                    " but content differs" % rep.device
                )
            else:
                td.ha_stats["kept_only_partner"] += 1
                note = (
                    "Partner firewall %s: rule not present on the"
                    " primary" % rep.device
                )
            origin = "secondary"
        td.rows.append(ConsRow(rep, raw, values, origin, note))


def make_rules(tabs, cfg):
    rules, uid = [], 0
    for td in tabs:
        if not td.rows:
            continue
        cols = role_columns(td.headers, cfg)
        missing = [
            r
            for r in ("name", "source", "destination", "service")
            if r not in cols
        ]
        if missing:
            raise AuditError(
                "Tab %s: could not find column(s) for %s in the headers"
                " %s. Add the header text to column_aliases in the"
                " config." % (td.name, ", ".join(missing), td.headers)
            )
        for i, cr in enumerate(td.rows):
            r = build_rule(
                cr.values,
                cols,
                td.name,
                td.layout,
                cfg,
                cr.report.filename,
                cr.raw.row_no,
                cr.origin,
            )
            r.uid, r.tab_row, r.ha_note, r.cons = (
                uid,
                i + 2,
                cr.ha_note,
                cr,
            )
            uid += 1
            rules.append(r)
    return rules


# === engine: coverage maths ===
def _segments(target_iv, line_ivs):
    pts = set()
    for a, b in target_iv:
        pts.add(a)
        pts.add(b + 1)
    for iv in line_ivs:
        for a, b in iv:
            pts.add(a)
            pts.add(b + 1)
    pts = sorted(pts)
    segs = []
    for i in range(len(pts) - 1):
        lo, hi = pts[i], pts[i + 1] - 1
        if any(a <= lo and hi <= b for a, b in target_iv):
            segs.append((lo, hi))
    return segs


def _classes(target_iv, per_line_iv):
    out = {}
    for lo, hi in _segments(target_iv, per_line_iv):
        sig = frozenset(
            i
            for i, iv in enumerate(per_line_iv)
            if any(a <= lo and hi <= b for a, b in iv)
        )
        rec = out.setdefault(sig, [0, (lo, hi)])
        rec[0] += hi - lo + 1
    return out


def uncovered_flows(src, dst, ports, lines):
    s_cls = _classes(src.iv, [l[0].iv for l in lines])
    d_cls = _classes(dst.iv, [l[1].iv for l in lines])
    p_cls = {}
    for proto, ivs in ports.d.items():
        for sig, (size, ex) in _classes(
            ivs, [l[2].d.get(proto, []) for l in lines]
        ).items():
            rec = p_cls.setdefault(sig, [0, (proto, ex)])
            rec[0] += size
    total = src.count() * dst.count() * ports.count()
    unc, example = 0, None
    for ssig, (ssz, sex) in s_cls.items():
        for dsig, (dsz, dex) in d_cls.items():
            both = ssig & dsig
            for psig, (psz, pex) in p_cls.items():
                if not (both & psig):
                    unc += ssz * dsz * psz
                    if example is None:
                        example = (sex, dex, pex)
    return unc, total, example


class Verdict(object):
    def __init__(self):
        self.status = "REVIEW"
        self.detail = self.merged_note = ""
        (
            self.rfc_used,
            self.rfc_missing,
            self.lines_used,
            self.notes,
            self.risky_ports,
        ) = ([], [], [], [], [])
        self.needed = None
        self.ex_src, self.ex_dst, self.ex_ports = (
            IPSet(),
            IPSet(),
            PortSet(),
        )
        self.unc = self.unc_total = 0
        self.risky_rule = self.shares_no_port = False
        self.override = None
        self.tool_status = None
        self.fingerprint = ""
        self.confidence = self.confidence_why = ""


def fmt_lines(lines):
    by = collections.OrderedDict()
    for rfc, sr in lines:
        by.setdefault(rfc, [])
        if sr not in by[rfc]:
            by[rfc].append(sr)
    return "; ".join(
        "RFC%s Sr %s" % (r, ",".join(str(x) for x in srs))
        for r, srs in by.items()
    )


def risky(rule, cfg):
    if rule.removed or rule.is_deny:
        return []
    hits = []
    for p in cfg["risky_ports"]:
        if str(p).upper() == "ANY":
            if rule.any_service or rule.ports.is_everything():
                hits.append("ANY")
        elif rule.ports.contains(int(p)):
            hits.append(str(p))
    if rule.src.is_any():
        hits.append("SRC:ANY")
    elif rule.src.count() >= 65536:
        hits.append("SRC:LARGE(/16+)")
    if rule.dst.is_any():
        hits.append("DST:ANY")
    elif rule.dst.count() >= 65536:
        hits.append("DST:LARGE(/16+)")
    return hits


_EXPIRY_WARN = {"days": 30}


def expiry_status(exp_val, ref_date=None, warn_days=None):
    if not exp_val:
        return ""
    if str(exp_val).strip().lower() == "permanent":
        return "PERMANENT"
    d = (
        exp_val.date()
        if isinstance(exp_val, datetime.datetime)
        else (exp_val if isinstance(exp_val, datetime.date) else _parse_date(exp_val))
    )
    if d is None and isinstance(exp_val, str):
        pt = parse_time(exp_val)
        if pt is not None:
            d = pt.date()
    if d is None:
        return ""
    ref = ref_date or datetime.date.today()
    days = (d - ref).days
    if days < 0:
        return "EXPIRED"
    if warn_days is None:
        warn_days = _EXPIRY_WARN["days"]
    if days <= warn_days:
        return "EXPIRING SOON (%dd)" % days
    return "ACTIVE"


def _effective(rule, cfg):
    if cfg["policy"]["edited_scope"] == "added" and rule.edited:
        return (
            rule.src_added if rule.edited_markers["src"] else IPSet(),
            rule.dst_added if rule.edited_markers["dst"] else IPSet(),
            (
                rule.ports_added
                if rule.edited_markers["svc"]
                else PortSet()
            ),
            True,
        )
    return rule.src, rule.dst, rule.ports, False


def _elsewhere(lines, ex_set, idx, rports):
    hit = [l for l in lines if l[idx].overlaps(ex_set)]
    if not hit:
        return " (these addresses are not in the RFC at all)"
    approved = PortSet()
    for l in hit:
        approved = approved | l[4]
    extra = rports - approved
    where = fmt_lines([(l[0], l[1]) for l in hit])
    if extra:
        return (
            " (they appear in %s, approved only for %s; the rule also"
            " opens %s to them)" % (where, approved.fmt(), extra.fmt())
        )
    return " (they appear in %s)" % where


def effective_rfcs(rule, cfg, sheets=None):
    chain = list(getattr(rule, "chain", None) or [])
    if not chain:
        return []
    mode = cfg["policy"].get("multi_rfc", "last")
    if mode == "last":
        sel = [chain[-1]]
    elif mode == "first":
        sel = [chain[0]]
    else:
        sel = chain
    if sheets is not None:
        sel = [n for n in sel if n in sheets]
    return sel


def smax_record(smax, rule, cfg):
    if not smax or not getattr(rule, "chain", None):
        return None
    mode = cfg["policy"].get("multi_rfc", "last")
    order = list(reversed(rule.chain)) if mode == "last" else list(rule.chain)
    return smax.lookup(order)


def evaluate_rule(rule, sheets, cfg):
    v = Verdict()
    pol = cfg["policy"]
    v.risky_ports = risky(rule, cfg)
    v.risky_rule = bool(v.risky_ports)
    if rule.removed:
        if pol.get("removed_rules", "skip") == "skip":
            v.status, v.detail = (
                "N/A",
                (
                    "Rule was removed (policy removed_rules=skip); nothing to"
                    " compare with an RFC port sheet."
                ),
            )
            return v
        v.notes.append("Removed rule checked per policy (removed_rules=check).")
    if rule.is_deny and pol["deny_rules"] == "skip":
        v.status, v.detail = (
            "N/A",
            (
                "Deny/drop rule (policy deny_rules=skip): not compared"
                " with the RFC port sheet."
            ),
        )
        return v
    if not rule.chain:
        v.detail = "No RFC number found in the rule name" + (
            " or description." if rule.desc_rfcs == [] else "."
        )
        return v
    if rule.rfc_source == "description":
        v.notes.append(
            "RFC number taken from the rule description because the"
            " name has none."
        )
    selected = effective_rfcs(rule, cfg)
    avail = [n for n in selected if n in sheets]
    v.rfc_missing = [n for n in selected if n not in sheets]
    if not avail:
        req_rfc = selected[0]
        v.needed = req_rfc
        v.detail = "RFC sheet for RFC%s not provided." % req_rfc
        if len(rule.chain) > 1:
            others = [n for n in rule.chain if n != req_rfc]
            if others:
                v.detail += " Other RFCs in the name: %s." % ", ".join(
                    "RFC" + n for n in others
                )
        return v
    v.rfc_used = avail
    lines = []
    for n in avail:
        for ln in sheets[n].lines:
            lines.append((n, ln.sr, ln.src, ln.dst, ln.ports))
            if ln.bidirectional:
                lines.append((n, ln.sr, ln.dst, ln.src, ln.ports))
    rsrc, rdst, rports, scoped = _effective(rule, cfg)
    if scoped and not (rsrc or rdst or rports):
        v.status = "NO"
        v.detail = (
            "Edited rule: this change adds no source, destination or"
            " service (policy edited_scope=added)."
        )
        return v
    label = "RFC" + "+".join(avail)
    rows = [l for l in lines if rports.overlaps(l[4])]
    all_ports = PortSet()
    for l in lines:
        all_ports = all_ports | l[4]
    if rports:
        v.ex_ports = rports - all_ports
    if rsrc and rports:
        ap = IPSet()
        for l in rows:
            ap = ap | l[2]
        v.ex_src = rsrc - ap
    if rdst and rports:
        ap = IPSet()
        for l in rows:
            ap = ap | l[3]
        v.ex_dst = rdst - ap
    v.lines_used = [(l[0], l[1]) for l in rows]
    v.shares_no_port = bool(rports) and not rows
    rp = rports.fmt()
    problems = []
    if v.ex_dst:
        problems.append(
            "Destination not approved for %s in %s: %s%s"
            % (
                rp,
                label,
                v.ex_dst.fmt(6),
                _elsewhere(lines, v.ex_dst, 3, rports),
            )
        )
    if v.ex_src:
        problems.append(
            "Source not approved for %s in %s: %s%s"
            % (
                rp,
                label,
                v.ex_src.fmt(6),
                _elsewhere(lines, v.ex_src, 2, rports),
            )
        )
    if v.ex_ports:
        if rule.any_service:
            problems.append(
                "Service is ANY (every port) but %s approves only %s"
                % (label, all_ports.fmt())
            )
        else:
            problems.append(
                "Port(s) not requested in %s: %s"
                % (label, v.ex_ports.fmt())
            )
    unresolved = []
    if rule.svc_unresolved:
        unresolved.append(
            "service name(s) not resolvable to ports: "
            + ", ".join(rule.svc_unresolved)
        )
    if rule.src_unresolved:
        unresolved.append(
            "source object(s) without an address: "
            + ", ".join(rule.src_unresolved)
        )
    if rule.dst_unresolved:
        unresolved.append(
            "destination object(s) without an address: "
            + ", ".join(rule.dst_unresolved)
        )
    if not rports and not scoped:
        unresolved.append(
            "no port could be read from the service column"
        )
    if not rsrc and not scoped:
        unresolved.append("no source address could be read")
    if not rdst and not scoped:
        unresolved.append("no destination address could be read")
    srs = fmt_lines(v.lines_used)
    if not problems and rsrc and rdst and rports and lines:
        if pol.get("combined_row_grouping", "enabled") == "strict":
            single_ok = any(
                not (rsrc - l[2]) and not (rdst - l[3]) and not (rports - l[4])
                for l in lines
            )
            if not single_ok:
                problems.append(
                    "Combined-row grouping is strict: no single RFC line approves the full source, destination and port set together"
                )
        else:
            unc, total, ex = uncovered_flows(
                rsrc, rdst, rports, [(l[2], l[3], l[4]) for l in lines]
            )
            v.unc, v.unc_total = unc, total
            if unc:
                (slo, shi), (dlo, dhi), (proto, (plo, phi)) = ex
                v.merged_note = (
                    "Broader than the RFC lines: %d of %d"
                    " source/destination/port flows are not approved"
                    " together by any single line, e.g. %s/%d from %s"
                    " to %s."
                    % (unc, total, proto, plo, i2ip(slo), i2ip(dlo))
                )
                if pol["merged_rule"] == "yes":
                    problems.append(v.merged_note)
    if problems:
        v.status = "YES"
        v.detail = "; ".join(problems) + (
            ". RFC lines sharing these ports: %s." % srs if srs else "."
        )
        if unresolved:
            v.notes.append(
                "Also not checked: " + "; ".join(unresolved) + "."
            )
    elif unresolved:
        v.detail = (
            "Cannot fully verify: "
            + "; ".join(unresolved)
            + ". What could be read matches %s (%s)." % (label, srs)
        )
    else:
        v.status = "NO"
        v.detail = "Source, destination and ports match %s." % srs
    if rule.svc_low:
        v.notes.append(
            "Ports for service name(s) %s were read from the object"
            " name (low confidence)." % ", ".join(rule.svc_low)
        )
    for n in avail:
        bad = [
            ln
            for ln in sheets[n].lines
            if ln.unk_ports or not ln.src or not ln.dst or not ln.ports
        ]
        if bad:
            v.notes.append(
                "RFC%s has line(s) the tool could not fully read (Sr"
                " %s); see Checks sheet."
                % (n, ",".join(str(b.sr) for b in bad))
            )
    if v.rfc_missing:
        v.notes.append(
            "RFC sheet not provided for %s in the rule name; only %s"
            " was used."
            % (
                ", ".join("RFC" + n for n in v.rfc_missing),
                ", ".join("RFC" + n for n in avail),
            )
        )
    if rule.enabled is False:
        v.notes.append("Rule is disabled.")
    if rule.is_deny:
        v.notes.append(
            "Rule action is %s; an RFC port sheet normally describes"
            " permitted traffic." % rule.action
        )
    return v


# === engine: RFC level ===
class LineCoverage(object):
    def __init__(self, rfc, line):
        self.rfc, self.line = rfc, line
        self.status, self.detail = "Not found", ""
        self.rules = []


class RfcResult(object):
    def __init__(self, sheet):
        self.sheet, self.number = sheet, sheet.number
        self.rules, self.coverage, self.notes = [], [], []
        self.impl, self.pir = "Not Implemented", "PIR Pending"
        self.counts = collections.Counter()


def _union(sets):
    out = IPSet()
    for s in sets:
        out = out | s
    return out


def line_coverage(rfc, ln, rules):
    cov = LineCoverage(rfc, ln)
    variants = [(ln.src, ln.dst)] + (
        [(ln.dst, ln.src)] if ln.bidirectional else []
    )
    hit = [
        r
        for r in rules
        if not (r.removed or r.is_deny)
        and any(
            r.src.overlaps(s) and r.dst.overlaps(d) for s, d in variants
        )
        and r.ports.overlaps(ln.ports)
    ]
    cov.rules = hit
    if not hit:
        cov.detail = (
            "No rule in the reports carrying this RFC overlaps this"
            " line."
        )
        return cov
    ms, md = ln.src - _union(r.src for r in hit), ln.dst - _union(
        r.dst for r in hit
    )
    mp = ln.ports
    for r in hit:
        mp = mp - r.ports
    parts = []
    if ms:
        parts.append("source not implemented: " + ms.fmt(5))
    if md:
        parts.append("destination not implemented: " + md.fmt(5))
    if mp:
        parts.append("port not implemented: " + mp.fmt())
    if parts:
        cov.status, cov.detail = "Partially covered", "; ".join(parts)
    else:
        cov.status = "Covered"
        cov.detail = (
            "Every source, destination and port of this line appears in"
            " a rule."
        )
        if any(r.enabled is False for r in hit):
            cov.detail += " (a covering rule is disabled)"
    return cov


def run_pir_test_case(rule_name, change_type, action, src_txt, dst_txt, svc_txt, rfc_lines_spec, cfg):
    r = Rule()
    r.tab = "TEST"
    r.layout = "PA"
    r.name = (rule_name or "").strip()
    r.change_type = (change_type or "Added").strip()
    r.action = (action or "Allow").strip()
    r.enabled = True
    digits = int(cfg["rfc"]["number_digits"])
    r.chain = []
    for n in re.findall(r"(?<!\d)(\d{%d})(?!\d)" % digits, r.name):
        if n not in r.chain:
            r.chain.append(n)
    ar_s = parse_addr_cell(src_txt or "")
    ar_d = parse_addr_cell(dst_txt or "")
    r.src, r.src_added, r.src_unresolved = ar_s.ips, ar_s.added, ar_s.unresolved
    r.dst, r.dst_added, r.dst_unresolved = ar_d.ips, ar_d.added, ar_d.unresolved
    r.any_src, r.any_dst = ar_s.any_addr, ar_d.any_addr
    toks = [("tcp/" + t if t.isdigit() else t) for t in (x.strip() for x in re.split(r"[,\n]+", svc_txt or "") if x.strip())]
    sv = parse_services(toks, cfg.get("named_services"))
    r.ports, r.ports_added, r.any_service, r.svc_tokens, r.svc_unresolved, r.svc_low = sv.ports, sv.ports, sv.any_service, toks, sv.unresolved, sv.low
    sheets = {}
    for idx, (rfc_no, sr_no, l_src, l_dst, l_port) in enumerate(rfc_lines_spec, 1):
        num_m = re.findall(r"(?<!\d)(\d{%d})(?!\d)" % digits, str(rfc_no or ""))
        num = num_m[0] if num_m else re.sub(r"\D", "", str(rfc_no or ""))
        if not num:
            continue
        sh = sheets.get(num)
        if sh is None:
            sh = RfcSheet(num, "Tester")
            sheets[num] = sh
        ln = RfcLine()
        ln.sr = sr_no or idx
        ln.src = parse_ip_text(l_src or "")
        ln.dst = parse_ip_text(l_dst or "")
        ln.ports, ln.unk_ports, _ = parse_rfc_ports(l_port or "")
        sh.lines.append(ln)
    v = evaluate_rule(r, sheets, cfg)
    return v, r


def evaluate_rfcs(sheets, rules, verdicts):
    results = []
    for number in sorted(sheets):
        sh = sheets[number]
        res = RfcResult(sh)
        res.rules = [r for r in rules if number in r.chain]
        carrying = [r for r in res.rules if not r.removed]
        res.coverage = [
            line_coverage(number, ln, carrying) for ln in sh.lines
        ]
        for r in res.rules:
            res.counts[verdicts[r.uid].status] += 1
        covered = sum(1 for c in res.coverage if c.status == "Covered")
        found = sum(1 for c in res.coverage if c.status != "Not found")
        if not carrying:
            res.impl = "Not Implemented"
            res.notes.append(
                "No rule in the reports provided carries RFC%s."
                % number
            )
        elif res.counts["YES"]:
            res.impl = "Incorrectly Implemented"
        elif res.counts["REVIEW"]:
            res.impl = "Unable to Verify"
        elif covered == len(res.coverage):
            res.impl = "Correctly Implemented"
        elif found == 0:
            res.impl = "Not Implemented"
        else:
            res.impl = "Partially Implemented"
        usable = [
            r
            for r in carrying
            if not r.is_deny and r.enabled is not False
        ]
        if res.impl == "Incorrectly Implemented":
            res.pir = "PIR Deviation Found"
        elif carrying and not usable:
            res.pir = "PIR Failed"
            res.notes.append(
                "Every rule carrying this RFC is disabled or a deny"
                " rule."
            )
        elif res.impl == "Correctly Implemented":
            res.pir = "PIR Verified"
        if sh.change_kind and 'delet' in sh.change_kind.lower():
            res.notes.append(
                "RFC asks for a Deletion; coverage by added rules is"
                " not the right test for it."
            )
        results.append(res)
    return results


def find_duplicates(rules):
    groups = collections.OrderedDict()
    for r in rules:
        if r.removed or not (r.src and r.dst and r.ports):
            continue
        key = (
            r.tab,
            tuple(r.src.iv),
            tuple(r.dst.iv),
            tuple(r.ports.items()),
            r.action.lower(),
            r.zones,
        )
        groups.setdefault(key, []).append(r)
    return [g for g in groups.values() if len(g) > 1]


def find_unexpected(rules, verdicts):
    out = []
    for r in rules:
        v = verdicts[r.uid]
        if not r.chain:
            out.append(
                (
                    r,
                    "No RFC number",
                    (
                        "The rule name and description carry no RFC"
                        " number, so the change cannot be traced to an"
                        " approved request."
                    ),
                )
            )
        elif v.status == "YES" and v.shares_no_port:
            out.append(
                (
                    r,
                    "Not in the RFC",
                    (
                        "No line of the RFC port sheet shares a port"
                        " with this rule."
                    ),
                )
            )
    return out


# === Asset Owner (from the RFC port sheets) ===
OWNER_TITLES = ("mr", "mrs", "ms", "miss", "dr", "shri", "smt")


# === reviewer overrides, confidence and explanation ===
# A reviewer can correct a tool verdict (false positive / false
# negative). Overrides live in a JSON file next to the tool and are
# keyed by a fingerprint of the rule content, so:
#   * the same rule in tomorrow's report is cleared automatically;
#   * if the rule changes (IPs, ports, action ...) the override no
#     longer applies and the rule is checked again.
# The tool verdict is never hidden: reports show both the tool verdict
# and the final (reviewed) verdict.
OVERRIDES_FILE = "fwaudit_overrides.json"
OVERRIDE_REASONS = (
    "Approved in another RFC",
    "RFC sheet not read correctly",
    "Object / group resolved manually",
    "Service name resolved manually",
    "Port type (TCP/UDP) confirmed",
    "Combined RFC lines approve it",
    "HA / mirror rule",
    "Accepted risk (exception)",
    "Rule change verified with RFC owner",
    "Tool verdict wrong - other",
    "Confirmed issue (false negative)",
)
OVERRIDE_STATES = ("proposed", "approved", "rejected", "revoked")
FINAL_STATUSES = ("YES", "NO", "REVIEW", "N/A")


def _canon(obj):
    if isinstance(obj, IPSet):
        return [list(x) for x in obj.iv]
    if isinstance(obj, PortSet):
        return dict((k, [list(x) for x in v]) for k, v in sorted(obj.d.items()))
    return obj


def rule_fingerprint(rule):
    """Stable hash of what the rule does (not of its row number)."""
    body = [
        rule.tab,
        rule.name.strip().lower(),
        rule.change_type.strip().lower(),
        rule.action.strip().lower(),
        _canon(rule.src),
        _canon(rule.dst),
        _canon(rule.ports),
        bool(rule.any_service),
        sorted(rule.src_unresolved),
        sorted(rule.dst_unresolved),
        sorted(rule.svc_unresolved),
        list(rule.chain),
    ]
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def load_overrides(path):
    if not path or not os.path.isfile(path):
        return {"version": 1, "overrides": []}
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
    except ValueError as e:
        raise AuditError("Overrides file %s is not valid JSON: %s" % (path, e))
    if isinstance(d, list):
        d = {"version": 1, "overrides": d}
    if not isinstance(d, dict) or not isinstance(d.get("overrides"), list):
        raise AuditError("Overrides file %s has no 'overrides' list" % path)
    return d


def save_overrides(data, path):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)
    return data


def new_override(rule, final_status, reason, comment, by, state="proposed",
                 expires=""):
    if final_status not in FINAL_STATUSES:
        raise AuditError("final status must be one of %s" % (FINAL_STATUSES,))
    if not (reason or "").strip():
        raise AuditError("An override needs a reason.")
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return {
        "id": hashlib.sha256(
            ("%s|%s|%s" % (rule_fingerprint(rule), now, os.urandom(8).hex())).encode()
        ).hexdigest()[:12],
        "tab": rule.tab,
        "rule": rule.name,
        "change_type": rule.change_type,
        "fingerprint": rule_fingerprint(rule),
        "final_status": final_status,
        "reason": reason.strip(),
        "comment": (comment or "").strip(),
        "by": by or "",
        "at": now,
        "state": state,
        "approved_by": by if state == "approved" else "",
        "approved_at": now if state == "approved" else "",
        "expires": (expires or "").strip(),
    }


def _ov_expired(ov, ref):
    e = (ov.get("expires") or "").strip()
    if not e:
        return False
    d = _parse_date(e)
    return d is not None and d < ref


def apply_overrides(ctx, data, require_approval=True):
    """Set the final verdict from approved overrides. Keeps the tool
    verdict in v.tool_status. Returns stats used by reports."""
    stats = {"applied": [], "stale": [], "expired": [], "pending": [],
             "unused": []}
    by_fp = {}
    by_name = {}
    for ov in data.get("overrides", []):
        st = ov.get("state", "proposed")
        if st in ("rejected", "revoked"):
            continue
        by_fp.setdefault(ov.get("fingerprint"), []).append(ov)
        by_name.setdefault((ov.get("tab"), (ov.get("rule") or "").strip().lower()), []).append(ov)
    used = set()
    for r in ctx.rules:
        v = ctx.verdicts[r.uid]
        v.tool_status = v.status
        fp = rule_fingerprint(r)
        v.fingerprint = fp
        cands = sorted(by_fp.get(fp, []), key=lambda o: o.get("at", ""), reverse=True)
        chosen = None
        for ov in cands:
            if _ov_expired(ov, ctx.report_date):
                stats["expired"].append((r, ov))
                used.add(ov.get("id"))
                continue
            if ov.get("state") == "approved" or not require_approval:
                chosen = ov
                break
            stats["pending"].append((r, ov))
            used.add(ov.get("id"))
        if chosen is not None:
            used.add(chosen.get("id"))
            v.override = chosen
            v.status = chosen["final_status"]
            stats["applied"].append((r, chosen))
            v.notes.append(
                "Reviewer override: tool verdict %s -> %s (%s; by %s%s)."
                % (v.tool_status, v.status, chosen.get("reason", ""),
                   chosen.get("by", ""),
                   (", approved by %s" % chosen["approved_by"])
                   if chosen.get("approved_by") and chosen.get("approved_by") != chosen.get("by") else "")
            )
        elif not cands:
            old = by_name.get((r.tab, r.name.strip().lower()), [])
            old = [o for o in old if o.get("fingerprint") != fp
                   and o.get("state") == "approved"]
            if old:
                stats["stale"].append((r, old[0]))
                used.add(old[0].get("id"))
                v.notes.append(
                    "An earlier reviewer override (%s) no longer applies:"
                    " the rule content changed, so it was checked again."
                    % old[0].get("reason", "")
                )
    for ov in data.get("overrides", []):
        if ov.get("id") not in used and ov.get("state") in ("approved", "proposed"):
            stats["unused"].append(ov)
    return stats


def compute_confidence(rule, v, sheets):
    """High / Medium / Low with the reasons, so a reader knows how far
    to trust the verdict without opening the files."""
    low, med = [], []
    if v.status == "N/A" and not getattr(v, "override", None):
        return "N/A", "Not compared (policy)."
    if not rule.chain:
        low.append("no RFC number in the rule name/description")
    if v.rfc_missing:
        low.append("RFC sheet missing: " + ", ".join("RFC" + n for n in v.rfc_missing))
    if rule.src_unresolved or rule.dst_unresolved:
        low.append("address object(s) without an IP")
    if rule.svc_unresolved:
        low.append("service name(s) not resolved")
    if (v.tool_status or v.status) == "REVIEW":
        low.append("tool could not fully verify")
    if rule.svc_low:
        med.append("port read from service name")
    if rule.rfc_source == "description":
        med.append("RFC number taken from description")
    if len(rule.chain) > 1:
        med.append("rule name has %d RFC numbers" % len(rule.chain))
    if v.merged_note:
        med.append("rule wider than any single RFC line")
    used = set(n for n, _ in v.lines_used)
    for n in used:
        sh = sheets.get(n)
        if sh is None:
            continue
        for ln in sh.lines:
            if ln.ports_assumed_proto and ln.ports:
                med.append("RFC%s Port Type blank, TCP assumed" % n)
                break
        if any("rows numbered by position" in w or "before the first" in w
               for w in sh.warnings):
            med.append("RFC%s rows had no Sr. No." % n)
    if low:
        return "Low", "; ".join(low + med)
    if med:
        return "Medium", "; ".join(med)
    return "High", "All addresses, ports and RFC lines were read exactly."


def explain_verdict(rule, v):
    """Step-by-step checks behind a verdict: (step, result, detail)."""
    out = []
    ok, bad, na = "PASS", "FAIL", "INFO"
    out.append(("RFC number in rule", ok if rule.chain else bad,
                ", ".join("RFC" + n for n in rule.chain) or "none found"
                + (" (from description)" if rule.rfc_source == "description" else "")))
    if rule.chain:
        out.append(("RFC port sheet available",
                    ok if v.rfc_used and not v.rfc_missing else bad,
                    ("used " + ", ".join("RFC" + n for n in v.rfc_used)) if v.rfc_used else
                    ("missing " + ", ".join("RFC" + n for n in v.rfc_missing))))
    if v.status == "N/A" and not getattr(v, "override", None):
        out.append(("Comparison", na, v.detail))
        return out
    unres = list(rule.src_unresolved) + list(rule.dst_unresolved)
    out.append(("Addresses readable", bad if unres else ok,
                ("not read: " + ", ".join(unres[:6])) if unres else "all objects have IPs"))
    out.append(("Services readable", bad if rule.svc_unresolved else ok,
                ("not read: " + ", ".join(rule.svc_unresolved[:6])) if rule.svc_unresolved
                else (rule.ports.fmt() or ("ANY" if rule.any_service else "-"))))
    if v.rfc_used:
        out.append(("Source inside RFC", bad if v.ex_src else ok,
                    ("not approved: " + v.ex_src.fmt()) if v.ex_src else rule.src.summary(4)))
        out.append(("Destination inside RFC", bad if v.ex_dst else ok,
                    ("not approved: " + v.ex_dst.fmt()) if v.ex_dst else rule.dst.summary(4)))
        out.append(("Ports inside RFC", bad if v.ex_ports else ok,
                    ("not approved: " + v.ex_ports.fmt()) if v.ex_ports else rule.ports.fmt()))
        if v.unc_total:
            out.append(("Same RFC line approves src+dst+port", bad if v.unc else ok,
                        v.merged_note or "every flow approved by one line"))
        out.append(("RFC lines matched", na, fmt_lines(v.lines_used) or "-"))
    if v.risky_ports:
        out.append(("Risk check", na, "risky: " + ", ".join(v.risky_ports)))
    tool = v.tool_status or v.status
    out.append(("Tool verdict", na, "PIR ISSUE = %s" % tool))
    ov = getattr(v, "override", None)
    if ov:
        out.append(("Reviewer override", na, "%s -> %s: %s%s" % (
            tool, v.status, ov.get("reason", ""),
            (" - " + ov["comment"]) if ov.get("comment") else "")))
    return out


def finalize_review(ctx, overrides_path=None, require_approval=True):
    """Apply overrides then compute confidence for every rule."""
    data = load_overrides(overrides_path) if overrides_path else {"overrides": []}
    ctx.overrides_path = overrides_path or ""
    ctx.override_stats = apply_overrides(ctx, data, require_approval)
    for r in ctx.rules:
        v = ctx.verdicts[r.uid]
        if v.tool_status is None:
            v.tool_status = v.status
        v.confidence, v.confidence_why = compute_confidence(r, v, ctx.sheets)
    return ctx.override_stats


def _resolve_overrides(cfg, overrides_path=None):
    if overrides_path is False or overrides_path == "":
        return None
    if overrides_path:
        return overrides_path
    f = (cfg.get("review") or {}).get("overrides_file") or ""
    if not f:
        return None
    if not os.path.isabs(f):
        f = os.path.join(tool_dir(), f)
    return f if os.path.isfile(f) else None


def results_to_dict(ctx, max_lines=200):
    """Everything a reviewer needs, as plain JSON-able data (used by the
    web UI and by `run --json`)."""
    rules = []
    used_sheets = ctx.sheets
    for r in ctx.rules:
        v = ctx.verdicts[r.uid]
        own = ctx.owners.get(r.uid, ("", ""))
        app = ctx.apps.get(r.uid, ("", ""))
        ev = []
        used_pairs = set((n, sr) for n, sr in v.lines_used)
        for n in (v.rfc_used or []):
            sh = used_sheets.get(n)
            if not sh:
                continue
            for ln in sh.lines[:max_lines]:
                ev.append({
                    "rfc": n, "sr": ln.sr, "sheet": ln.sheet, "row": ln.row,
                    "src": ln.src_text, "dst": ln.dst_text, "port": ln.port_text,
                    "ports": ln.ports.fmt(),
                    "direction": ln.direction, "justification": ln.justification,
                    "src_hit": bool(r.src and ln.src.overlaps(r.src)),
                    "dst_hit": bool(r.dst and ln.dst.overlaps(r.dst)),
                    "port_hit": bool(r.ports and ln.ports.overlaps(r.ports)),
                    "used": (n, ln.sr) in used_pairs,
                    "file": sh.filename,
                })
        ov = getattr(v, "override", None)
        rules.append({
            "uid": r.uid, "tab": r.tab, "tab_row": r.tab_row,
            "firewall": r.cons.report.device if r.cons else "",
            "file": r.file, "file_row": r.file_row,
            "change_type": r.change_type, "name": r.name,
            "action": r.action, "enabled": r.enabled,
            "description": r.description,
            "rfcs": list(r.chain), "rfc_used": list(v.rfc_used),
            "rfc_missing": list(v.rfc_missing),
            "src": r.src.summary(8) if r.src else "",
            "dst": r.dst.summary(8) if r.dst else "",
            "services": ", ".join(r.svc_tokens), "ports": r.ports.fmt(),
            "status": v.status, "tool_status": v.tool_status or v.status,
            "detail": v.detail, "notes": list(v.notes),
            "merged_note": v.merged_note,
            "lines_used": fmt_lines(v.lines_used),
            "risky": bool(v.risky_rule), "risky_ports": list(v.risky_ports),
            "not_approved": {"src": v.ex_src.fmt() if v.ex_src else "",
                             "dst": v.ex_dst.fmt() if v.ex_dst else "",
                             "ports": v.ex_ports.fmt() if v.ex_ports else ""},
            "confidence": getattr(v, "confidence", ""),
            "confidence_why": getattr(v, "confidence_why", ""),
            "fingerprint": getattr(v, "fingerprint", "") or rule_fingerprint(r),
            "override": ov,
            "asset_owner": own[0] if own else "",
            "application": app[0] if app else "",
            "explain": [list(x) for x in explain_verdict(r, v)],
            "evidence": ev,
        })
    st = collections.Counter(x["status"] for x in rules)
    tst = collections.Counter(x["tool_status"] for x in rules)
    os_ = getattr(ctx, "override_stats", {}) or {}
    return {
        "tool_version": VERSION,
        "run_time": ctx.run_time,
        "report_date": ctx.report_date.strftime("%Y-%m-%d"),
        "operator": ctx.operator,
        "config_hash": ctx.config_hash,
        "status": ctx.status,
        "counts": dict(st), "tool_counts": dict(tst),
        "confidence_counts": dict(collections.Counter(x["confidence"] for x in rules)),
        "overrides": {k: len(os_.get(k, [])) for k in ("applied", "stale", "expired", "pending", "unused")},
        "warnings": [list(w) for w in ctx.warnings],
        "sheet_problems": [list(p) for p in ctx.sheet_problems],
        "rfc_sheets": [
            {"rfc": s.number, "file": s.filename,
             "sheets": getattr(s, "sheets", [s.sheet]),
             "layouts": [list(x) for x in getattr(s, "layouts", [])],
             "lines": len(s.lines), "warnings": list(s.warnings)}
            for s in sorted(ctx.sheets.values(), key=lambda x: x.number)
        ],
        "input_custody": ctx.input_custody,
        "output_custody": ctx.output_custody,
        "rules": rules,
    }


def _reviewer_sheet(ctx, ws):
    title_block(
        ws, "Reviewer Overrides — Tool Verdict vs Final Verdict",
        ["Final verdicts in this workbook include approved reviewer"
         " overrides. The tool verdict is kept for audit.",
         "Overrides file: %s" % (getattr(ctx, "overrides_path", "") or "(none)")],
    )
    hdr = ["Tab", "Row in tab", "Rule name", "Change type", "Tool verdict",
           "Final verdict", "State", "Reason", "Comment", "Proposed by",
           "Proposed at", "Approved by", "Approved at", "Expires",
           "Fingerprint"]
    rows = []
    st = getattr(ctx, "override_stats", {}) or {}
    for kind, label in (("applied", "APPLIED"), ("pending", "PENDING APPROVAL"),
                        ("stale", "NOT APPLIED - RULE CHANGED"),
                        ("expired", "EXPIRED")):
        for r, ov in st.get(kind, []):
            v = ctx.verdicts[r.uid]
            rows.append([
                r.tab, r.tab_row, r.name, r.change_type,
                v.tool_status or v.status,
                v.status if kind == "applied" else ov.get("final_status", ""),
                label, ov.get("reason", ""), ov.get("comment", ""),
                ov.get("by", ""), ov.get("at", ""), ov.get("approved_by", ""),
                ov.get("approved_at", ""), ov.get("expires", ""),
                ov.get("fingerprint", ""),
            ])
    for ov in st.get("unused", []):
        rows.append([ov.get("tab", ""), "", ov.get("rule", ""),
                     ov.get("change_type", ""), "", ov.get("final_status", ""),
                     "NOT IN THIS RUN", ov.get("reason", ""),
                     ov.get("comment", ""), ov.get("by", ""), ov.get("at", ""),
                     ov.get("approved_by", ""), ov.get("approved_at", ""),
                     ov.get("expires", ""), ov.get("fingerprint", "")])
    table(ws, 5, hdr, rows,
          [12, 8, 30, 10, 10, 10, 22, 30, 40, 14, 18, 14, 18, 12, 26],
          status_cols=(5, 6), center_cols=(2, 4))


def owner_key(name):
    words = re.sub(r'[.,]+', ' ', name.lower()).split()
    while len(words) > 1 and words[0] in OWNER_TITLES:
        words.pop(0)
    return " ".join(words)


def _add_owners(bucket, names, ignore):
    for n in names:
        k = owner_key(n)
        if k and k not in ignore and k not in bucket:
            bucket[k] = n


def asset_owner(rule, sheets, cfg, smax=None):
    """Return (text, basis). Read from the RFC sheet, never guessed."""
    ac = cfg["asset_owner"]
    ignore = set(owner_key(x) for x in ac["ignore"])
    chain = effective_rfcs(rule, cfg, sheets)
    lines = [(n, ln) for n in chain for ln in sheets[n].lines]
    hit = [
        (n, ln)
        for n, ln in lines
        if (rule.src.overlaps(ln.src) and rule.dst.overlaps(ln.dst))
        or (
            ln.bidirectional
            and rule.src.overlaps(ln.dst)
            and rule.dst.overlaps(ln.src)
        )
    ]
    how = " (lines matching the rule)"
    if not hit:
        hit = lines
        how = " (all lines; none matches the rule's addresses)"
    src, dst = collections.OrderedDict(), collections.OrderedDict()
    for n, ln in hit:
        _add_owners(src, ln.src_owners, ignore)
        _add_owners(dst, ln.dst_owners, ignore)
    s, d = list(src.values()), list(dst.values())
    show = ac["show"]
    if show == "source":
        text = "; ".join(s)
    elif show == "destination":
        text = "; ".join(d)
    elif s and set(src) == set(dst):
        text = "; ".join(s)
    else:
        parts = []
        if s:
            parts.append("Source: " + "; ".join(s))
        if d:
            parts.append("Destination: " + "; ".join(d))
        text = " | ".join(parts)
    if text:
        return text, fmt_lines([(n, ln.sr) for n, ln in hit]) + how
    rec = None
    if smax and ac["smax_fallback"]:
        rec = smax_record(smax, rule, cfg)
    if rec and rec.get("asset_owner"):
        return rec["asset_owner"], "SMAX export (RFC sheet has none)"
    if not rule.chain:
        return "", "no RFC number in the rule"
    if not chain:
        return "", "RFC sheet not provided"
    return "", "no owner written in the RFC sheet"

def rule_application(rule, sheets, cfg, smax=None):
    """Return Application string from RFC sheet (Source/Dest Application), with SMAX fallback."""
    ac = cfg["asset_owner"]
    ignore = set(owner_key(x) for x in ac["ignore"])
    chain = effective_rfcs(rule, cfg, sheets)
    lines = [(n, ln) for n in chain for ln in sheets[n].lines]
    hit = [
        (n, ln)
        for n, ln in lines
        if (rule.src.overlaps(ln.src) and rule.dst.overlaps(ln.dst))
        or (
            ln.bidirectional
            and rule.src.overlaps(ln.dst)
            and rule.dst.overlaps(ln.src)
        )
    ]
    if not hit:
        hit = lines
    src_b, dst_b = collections.OrderedDict(), collections.OrderedDict()
    for _, ln in hit:
        for a in ln.src_apps:
            k = re.sub(r"\s+", " ", a.lower()).strip()
            if k and k not in ignore and k not in src_b:
                src_b[k] = a
        for a in ln.dst_apps:
            k = re.sub(r"\s+", " ", a.lower()).strip()
            if k and k not in ignore and k not in dst_b:
                dst_b[k] = a
    s, d = list(src_b.values()), list(dst_b.values())
    if s and set(src_b) == set(dst_b):
        text = "; ".join(s)
    else:
        parts = []
        if s:
            parts.append("Source: " + "; ".join(s))
        if d:
            parts.append("Destination: " + "; ".join(d))
        text = " | ".join(parts)
    if text:
        return text
    if smax and ac["smax_fallback"]:
        rec = smax_record(smax, rule, cfg)
        if rec and rec.get("application"):
            return rec["application"]
    return ""



# === xlsx writer (zipfile + xml only) ===
def sty(
    bold=False,
    italic=False,
    color="000000",
    size=10,
    fill=None,
    border=True,
    h=None,
    v="top",
    wrap=True,
    fmt=None,
):
    return (bold, italic, color, size, fill, border, h, v, wrap, fmt)


NORM = sty()
BOLD = sty(bold=True, border=False, wrap=False)
HEAD = sty(bold=True, color="FFFFFF", fill="1F3864", v="center")
AUTOHEAD = sty(bold=True, color="FFFFFF", fill="2E75B6", v="center")
TITLE = sty(
    bold=True, color="1F3864", size=14, border=False, wrap=False
)
SUB = sty(italic=True, color="595959", border=False, wrap=False)
CENTER = sty(h="center")
YELLOW = sty(fill="FFEB9C")
STATUS_FILL = {
    "YES": ("FFC7CE", "9C0006"),
    "NO": ("C6EFCE", "006100"),
    "REVIEW": ("FFEB9C", "9C5700"),
    "N/A": ("E7E6E6", "595959"),
    "Correctly Implemented": ("C6EFCE", "006100"),
    "Incorrectly Implemented": ("FFC7CE", "9C0006"),
    "Partially Implemented": ("FFEB9C", "9C5700"),
    "Not Implemented": ("FFC7CE", "9C0006"),
    "Unable to Verify": ("FFEB9C", "9C5700"),
    "PIR Verified": ("C6EFCE", "006100"),
    "PIR Deviation Found": ("FFC7CE", "9C0006"),
    "PIR Failed": ("FFC7CE", "9C0006"),
    "PIR Pending": ("FFEB9C", "9C5700"),
    "PIR Evidence Missing": ("FFEB9C", "9C5700"),
    "PASS": ("C6EFCE", "006100"),
    "ATTENTION REQUIRED": ("FFC7CE", "9C0006"),
    "INCOMPLETE": ("FFEB9C", "9C5700"),
    "OK": ("C6EFCE", "006100"),
    "MISMATCH": ("FFC7CE", "9C0006"),
    "Covered": ("C6EFCE", "006100"),
    "Partially covered": ("FFEB9C", "9C5700"),
    "Not found": ("FFC7CE", "9C0006"),
    "ERROR": ("FFC7CE", "9C0006"),
    "WARN": ("FFEB9C", "9C5700"),
    "INFO": ("DDEBF7", "1F3864"),
}


def status_sty(v):
    if isinstance(v, str) and v in STATUS_FILL:
        bg, fg = STATUS_FILL[v]
        return sty(bold=True, color=fg, fill=bg, h="center")
    return None


def _colname(n):
    s = ""
    while n:
        n, rem = divmod(n - 1, 26)
        s = chr(65 + rem) + s
    return s


def _safe(v):
    if isinstance(v, str):
        v = "".join(
            ch
            for ch in v
            if ch in "\n\t"
            or (
                ord(ch) >= 32
                and ord(ch) not in (0xFFFE, 0xFFFF)
                and not 0xD800 <= ord(ch) <= 0xDFFF
            )
        )
        if len(v) > 32000:
            v = v[:31980] + " ...(truncated)"
    return v


class Sheet(object):
    def __init__(self, name):
        self.name = name
        self.cells, self.widths, self.heights, self.merges = (
            {},
            {},
            {},
            [],
        )
        self.freeze = self.filter = self.zoom = None
        self.fit, self.grid = False, True

    def put(self, r, c, v, style=NORM):
        style = style or NORM
        if (
            isinstance(v, (datetime.date, datetime.datetime))
            and style[9] is None
        ):
            style = style[:9] + ("DD-MMM-YYYY",)
        self.cells[(r, c)] = (_safe(v), style)

    def raw(self, r, c, v):
        self.cells[(r, c)] = (_safe(v), None)

    def val(self, r, c):
        return self.cells.get((r, c), (None, None))[0]

    def restyle(self, r, c, style):
        if style and (r, c) in self.cells:
            self.cells[(r, c)] = (self.cells[(r, c)][0], style)

    def set_widths(self, ws_):
        for i, w in enumerate(ws_, 1):
            self.widths[i] = w

    def widen(self, i, w):
        self.widths[i] = max(self.widths.get(i, 0), w)

    def merge(self, r1, c1, r2, c2):
        self.merges.append(
            "%s%d:%s%d" % (_colname(c1), r1, _colname(c2), r2)
        )


class Book(object):
    def __init__(self):
        self.sheets, self._xf, self._xfs = [], {}, []
        self.xf(sty(border=False, wrap=False, v=None))

    def sheet(self, name):
        ws = Sheet(name)
        self.sheets.append(ws)
        return ws

    def xf(self, style):
        if style not in self._xf:
            self._xf[style] = len(self._xfs)
            self._xfs.append(style)
        return self._xf[style]

    def _cell(self, r, c, v, style):
        ref = "%s%d" % (_colname(c), r)
        s = self.xf(style) if style else 0
        sa = ' s="%d"' % s if s else ""
        if v is None:
            return '<c r="%s"%s/>' % (ref, sa)
        if isinstance(v, bool):
            return '<c r="%s"%s t="b"><v>%d</v></c>' % (
                ref,
                sa,
                1 if v else 0,
            )
        if isinstance(v, (int, float)):
            return '<c r="%s"%s><v>%s</v></c>' % (ref, sa, repr(v))
        if isinstance(v, (datetime.date, datetime.datetime)):
            d = (
                v
                if isinstance(v, datetime.datetime)
                else datetime.datetime(v.year, v.month, v.day)
            )
            delta = d - datetime.datetime(1899, 12, 30)
            return '<c r="%s"%s><v>%s</v></c>' % (
                ref,
                sa,
                repr(delta.days + delta.seconds / 86400.0),
            )
        return (
            '<c r="%s"%s t="inlineStr"><is><t'
            ' xml:space="preserve">%s</t></is></c>'
            % (ref, sa, _xesc(str(v)))
        )

    def _sheet_xml(self, ws, first):
        rows = {}
        for (r, c), (v, s) in ws.cells.items():
            rows.setdefault(r, []).append((c, v, s))
        for r in ws.heights:
            rows.setdefault(r, [])
        maxr = max(rows) if rows else 1
        maxc = max([c for (r, c) in ws.cells] or [1])
        o = [
            '<?xml version="1.0" encoding="UTF-8"'
            ' standalone="yes"?>\n<worksheet xmlns="%s">' % _NS[1:-1]
        ]
        if ws.fit:
            o.append('<sheetPr><pageSetUpPr fitToPage="1"/></sheetPr>')
        o.append('<dimension ref="A1:%s%d"/>' % (_colname(maxc), maxr))
        view = '<sheetView workbookViewId="0"%s%s%s>' % (
            ' tabSelected="1"' if first else "",
            "" if ws.grid else ' showGridLines="0"',
            ' zoomScale="%d"' % ws.zoom if ws.zoom else "",
        )
        if ws.freeze:
            fr, fc = ws.freeze
            xs, ys = fc - 1, fr - 1
            pane = (
                "bottomRight"
                if xs and ys
                else ("topRight" if xs else "bottomLeft")
            )
            view += (
                '<pane%s%s topLeftCell="%s%d" activePane="%s"'
                ' state="frozen"/><selection pane="%s"/>'
                % (
                    ' xSplit="%d"' % xs if xs else "",
                    ' ySplit="%d"' % ys if ys else "",
                    _colname(fc),
                    fr,
                    pane,
                    pane,
                )
            )
        o.append("<sheetViews>%s</sheetView></sheetViews>" % view)
        o.append('<sheetFormatPr defaultRowHeight="15"/>')
        if ws.widths:
            o.append(
                "<cols>%s</cols>"
                % "".join(
                    '<col min="%d" max="%d" width="%s"'
                    ' customWidth="1"/>' % (c, c, w)
                    for c, w in sorted(ws.widths.items())
                )
            )
        o.append("<sheetData>")
        for r in sorted(rows):
            ht = (
                ' ht="%s" customHeight="1"' % ws.heights[r]
                if r in ws.heights
                else ""
            )
            o.append(
                '<row r="%d"%s>%s</row>'
                % (
                    r,
                    ht,
                    "".join(
                        self._cell(r, c, v, s)
                        for c, v, s in sorted(
                            rows[r], key=lambda x: x[0]
                        )
                    ),
                )
            )
        o.append("</sheetData>")
        if ws.filter:
            o.append('<autoFilter ref="%s"/>' % ws.filter)
        if ws.merges:
            o.append(
                '<mergeCells count="%d">%s</mergeCells>'
                % (
                    len(ws.merges),
                    "".join(
                        '<mergeCell ref="%s"/>' % m for m in ws.merges
                    ),
                )
            )
        o.append(
            '<pageMargins left="0.5" right="0.5" top="0.6" bottom="0.6"'
            ' header="0.3" footer="0.3"/>'
        )
        o.append(
            '<pageSetup paperSize="9" orientation="landscape"%s/>'
            % (' fitToWidth="1" fitToHeight="0"' if ws.fit else "")
        )
        o.append("</worksheet>")
        return "".join(o)

    def _styles_xml(self):
        fonts, fills, nfs, xfs = {}, {}, {}, []
        for b, i, col, size, fill, border, h, v, wrap, fmt in self._xfs:
            fo = fonts.setdefault((b, i, col, size), len(fonts))
            fi = fills.setdefault(fill, len(fills) + 2) if fill else 0
            nf = nfs.setdefault(fmt, 164 + len(nfs)) if fmt else 0
            al = "".join(
                [
                    ' horizontal="%s"' % h if h else "",
                    ' vertical="%s"' % v if v else "",
                    ' wrapText="1"' if wrap else "",
                ]
            )
            xfs.append(
                '<xf numFmtId="%d" fontId="%d" fillId="%d"'
                ' borderId="%d" xfId="0" applyNumberFormat="1"'
                ' applyFont="1" applyFill="1" applyBorder="1"'
                ' applyAlignment="1"><alignment%s/></xf>'
                % (nf, fo, fi, 1 if border else 0, al)
            )
        font_xml = "".join(
            '<font>%s%s<sz val="%d"/><color rgb="FF%s"/><name'
            ' val="Arial"/></font>'
            % (
                "<b/>" if k[0] else "",
                "<i/>" if k[1] else "",
                k[3],
                k[2],
            )
            for k, _ in sorted(fonts.items(), key=lambda x: x[1])
        )
        fill_xml = (
            '<fill><patternFill'
            ' patternType="none"/></fill><fill><patternFill'
            ' patternType="gray125"/></fill>'
            + "".join(
                '<fill><patternFill patternType="solid"><fgColor'
                ' rgb="FF%s"/><bgColor'
                ' indexed="64"/></patternFill></fill>' % k
                for k, _ in sorted(fills.items(), key=lambda x: x[1])
            )
        )
        side = '<%s style="thin"><color rgb="FFBFBFBF"/></%s>'
        border_xml = (
            "<border><left/><right/><top/><bottom/><diagonal/></"
            "border><border>%s</border>"
            % "".join(
                side % (s, s)
                for s in ("left", "right", "top", "bottom")
            )
            + ""
        )
        nf_xml = "".join(
            '<numFmt numFmtId="%d" formatCode="%s"/>' % (i, _xesc(c))
            for c, i in nfs.items()
        )
        return (
            '<?xml version="1.0" encoding="UTF-8"'
            ' standalone="yes"?>\n<styleSheet xmlns="%s">%s<fonts'
            ' count="%d">%s</fonts><fills count="%d">%s</fills><borders'
            ' count="2">%s</borders><cellStyleXfs count="1"><xf'
            ' numFmtId="0" fontId="0" fillId="0"'
            ' borderId="0"/></cellStyleXfs><cellXfs'
            ' count="%d">%s</cellXfs><cellStyles count="1"><cellStyle'
            ' name="Normal" xfId="0"'
            ' builtinId="0"/></cellStyles></styleSheet>'
            % (
                _NS[1:-1],
                (
                    '<numFmts count="%d">%s</numFmts>'
                    % (len(nfs), nf_xml)
                    if nfs
                    else ""
                ),
                len(fonts),
                font_xml,
                len(fills) + 2,
                fill_xml,
                border_xml,
                len(xfs),
                "".join(xfs),
            )
        )

    def save(self, path):
        sheets_xml = [
            self._sheet_xml(ws, i == 0)
            for i, ws in enumerate(self.sheets)
        ]
        styles = self._styles_xml()
        n = len(self.sheets)
        ct = (
            '<?xml version="1.0" encoding="UTF-8"'
            ' standalone="yes"?>\n<Types'
            ' xmlns="http://schemas.openxmlformats.'
            'org/package/2006/content-types"><Default Extension="rels"'
            ' ContentType="application/vnd.openxmlformats-'
            'package.relationships+xml"/><Default Extension="xml"'
            ' ContentType="application/xml"/><Override '
            'PartName="/xl/workbook.xml"'
            ' ContentType="application/vnd.openxmlformats-'
            'officedocument.spreadsheetml.'
            'sheet.main+xml"/><Override PartName="/xl/styles.xml"'
            ' ContentType="application/vnd.openxmlformats-'
            'officedocument.spreadsheetml.styles+xml"/>%s</Types>'
            % "".join(
                '<Override PartName="/xl/worksheets/sheet%d.xml"'
                ' ContentType="application/vnd.openxmlformats-'
                'officedocument.spreadsheetml.worksheet+xml"/>'
                % (i + 1)
                for i in range(n)
            )
        )
        rels = (
            '<?xml version="1.0" encoding="UTF-8"'
            ' standalone="yes"?>\n<Relationships'
            ' xmlns="http://schemas.openxmlformats.org/package/2006/'
            'relationships"><Relationship'
            ' Id="rId1"'
            ' Type="http://schemas.openxmlformats.org/officeDocument/'
            '2006/relationships/officeDocument"'
            ' Target="xl/workbook.xml"/></Relationships>'
        )
        rid = _OFF + "/relationships"
        wb = (
            '<?xml version="1.0" encoding="UTF-8"'
            ' standalone="yes"?>\n<workbook xmlns="%s"'
            ' xmlns:r="%s"><bookViews><workbookView'
            ' activeTab="0"/></bookViews><sheets>%s</sheets></workbook>'
            % (
                _NS[1:-1],
                rid,
                "".join(
                    '<sheet name="%s" sheetId="%d" r:id="rId%d"/>'
                    % (_xesc(ws.name, {'"': "&quot;"}), i + 1, i + 1)
                    for i, ws in enumerate(self.sheets)
                ),
            )
        )
        wbrels = (
            '<?xml version="1.0" encoding="UTF-8"'
            ' standalone="yes"?>\n<Relationships'
            ' xmlns="http://schemas.openxmlformats.org/package/2006/'
            'relationships">%s<Relationship'
            ' Id="rId%d" Type="%s/styles"'
            ' Target="styles.xml"/></Relationships>'
            % (
                "".join(
                    '<Relationship Id="rId%d" Type="%s/worksheet"'
                    ' Target="worksheets/sheet%d.xml"/>'
                    % (i + 1, rid, i + 1)
                    for i in range(n)
                ),
                n + 1,
                rid,
            )
        )
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", ct)
            z.writestr("_rels/.rels", rels)
            z.writestr("xl/workbook.xml", wb)
            z.writestr("xl/_rels/workbook.xml.rels", wbrels)
            z.writestr("xl/styles.xml", styles)
            for i, x in enumerate(sheets_xml):
                z.writestr("xl/worksheets/sheet%d.xml" % (i + 1), x)


def header_row(ws, row, labels, fills=None, height=32):
    for i, t in enumerate(labels, 1):
        ws.put(row, i, t, (fills or {}).get(i, HEAD))
    ws.heights[row] = height


def title_block(ws, title, lines=()):
    ws.put(1, 1, title, TITLE)
    for i, t in enumerate(lines, 2):
        ws.put(i, 1, t, SUB)
    ws.grid = False


def table(
    ws,
    top,
    labels,
    rows,
    widths=None,
    status_cols=(),
    center_cols=(),
    freeze=True,
    filt=True,
    fills=None,
):
    header_row(ws, top, labels, fills)
    for ri, vals in enumerate(rows, top + 1):
        for ci, v in enumerate(vals, 1):
            st = CENTER if ci in center_cols else NORM
            if ci in status_cols and v:
                st = status_sty(v) or st
            ws.put(ri, ci, v, st)
    last = top + len(rows)
    if widths:
        ws.set_widths(widths)
    if filt and rows:
        ws.filter = "A%d:%s%d" % (top, _colname(len(labels)), last)
    if freeze:
        ws.freeze = (top + 1, 1)
    return last


# === daily consolidated workbook ===
AUTO_COLS = (
    "RISKY RULES",
    "RISKY Ports",
    "PIR ISSUE",
    "Expiry",
    "Title",
    "RFC Owner",
    "Asset Owner",
    "Application",
    "RFC Application",
)
EXTRA = [
    "PIR DETAIL",
    "MERGED-RULE NOTE",
    "RFC SHEET USED",
    "ASSET OWNER FROM",
    "SOURCE FILE",
    "SOURCE ROW",
    "HA NOTE",
]
WIDTHS = {
    "change type": 11,
    "name": 26,
    "no.": 8,
    "change time": 20,
    "changed by": 14,
    "source": 34,
    "destination": 34,
    "service": 26,
    "services & applications": 26,
    "pir issue": 11,
    "risky rules": 10,
    "risky ports": 12,
    "it security": 22,
    "expiry": 14,
    "title": 30,
    "rfc owner": 28,
    "asset owner": 38,
    "asset owner from": 44,
    "application": 22,
    "rfc application": 22,
    "pir detail": 60,
    "merged-rule note": 44,
    "rfc sheet used": 22,
    "source file": 70,
    "source row": 9,
    "ha note": 34,
    "description": 30,
    "comments": 30,
    "date": 12,
    "prepared by": 16,
}
SMAX_FIELD = {
    "Title": "title",
    "RFC Owner": "rfc_owner",
    "Asset Owner": "asset_owner",
    "Application": "application",
    "Expiry": "expiry",
}


def out_layout(td, cfg):
    raw = (
        list(td.headers)
        if td.headers
        else list(cfg["layout_headers"][td.layout])
    )
    svc = role_columns(raw, cfg).get("service")
    cut = svc + 1 if svc is not None else len(raw)
    raw_low = set(h.strip().lower() for h in raw if h)
    manual = [
        "RFC Application" if (h == "Application" and "application" in raw_low) else h
        for h in cfg["manual_columns"]
    ]
    return (
        raw,
        raw[:cut]
        + manual
        + raw[cut:]
        + ["Date", "PREPARED BY"]
        + EXTRA,
        cut,
        len(manual),
    )


def write_daily(ctx, path):
    cfg = ctx.cfg
    bk = Book()
    summary = bk.sheet("Summary")
    by_tab = collections.OrderedDict((td.name, []) for td in ctx.tabs)
    for r in ctx.rules:
        by_tab[r.tab].append(r)
    for td in ctx.tabs:
        ws = bk.sheet(td.name)
        raw, headers, cut, nman = out_layout(td, cfg)
        fills = dict(
            (i, AUTOHEAD)
            for i, h in enumerate(headers, 1)
            if (cut < i <= cut + nman and h in AUTO_COLS) or h in EXTRA
        )
        header_row(ws, 1, headers, fills)
        rules = by_tab[td.name]
        for ri, r in enumerate(rules, 2):
            v = ctx.verdicts[r.uid]
            vals = [
                x.replace("_x000D_", "") if isinstance(x, str) else x
                for x in r.values
            ]
            rec = smax_record(ctx.smax, r, ctx.cfg)
            owner_text, owner_basis = ctx.owners[r.uid]
            manual = []
            for h in cfg["manual_columns"]:
                if h == "RISKY RULES":
                    manual.append("YES" if v.risky_rule else "NO")
                elif h == "RISKY Ports":
                    manual.append(", ".join(v.risky_ports))
                elif h == "PIR ISSUE":
                    manual.append(v.status)
                elif h == "Asset Owner":
                    manual.append(owner_text)
                elif h in ("RFC Application", "Application"):
                    manual.append(ctx.apps.get(r.uid, ""))
                elif h == "Expiry":
                    if rec is not None:
                        manual.append(rec.get("expiry") or "Permanent")
                    else:
                        manual.append("")
                elif rec is not None and h in SMAX_FIELD:
                    manual.append(rec[SMAX_FIELD[h]])
                else:
                    manual.append("")
            row = (
                vals[:cut]
                + manual
                + vals[cut:]
                + [ctx.report_date, ctx.operator]
            )
            detail = v.detail + (
                (" " + " ".join(v.notes)) if v.notes else ""
            )
            row += [
                detail,
                v.merged_note,
                ", ".join("RFC" + n for n in v.rfc_used),
                owner_basis,
                r.file,
                r.file_row,
                r.ha_note,
            ]
            zebra = sty(fill="F8FAFC") if (ri % 2 == 0) else NORM
            for ci, val in enumerate(row, 1):
                h = headers[ci - 1]
                st = zebra
                if h in ("PIR ISSUE", "RISKY RULES"):
                    st = status_sty(val) or zebra
                elif h == "MERGED-RULE NOTE" and val:
                    st = YELLOW
                elif h == "Change Type":
                    ct_l = clean(val).strip().lower()
                    if ct_l == "added":
                        st = sty(fill="E2EFDA", bold=True, h="center")
                    elif ct_l == "edited":
                        st = sty(fill="FFF2CC", bold=True, h="center")
                    elif ct_l in ("removed", "deleted"):
                        st = sty(fill="FCE4D6", bold=True, h="center")
                elif h == "Expiry":
                    es = expiry_status(val, ctx.report_date)
                    if es == "EXPIRED":
                        st = status_sty("YES")
                    elif es.startswith("EXPIRING SOON"):
                        st = YELLOW
                ws.put(ri, ci, val, st)
        for i, h in enumerate(headers, 1):
            ws.widths[i] = WIDTHS.get(h.strip().lower(), 16)
        ws.freeze, ws.zoom = (2, 3), 90
        if rules:
            ws.filter = "A1:%s%d" % (
                _colname(len(headers)),
                len(rules) + 1,
            )
    _summary(ctx, summary, by_tab)
    summary.fit = True
    bk.save(path)
    return path


def _summary(ctx, ws, by_tab):
    title_block(
        ws,
        "DXC Technology — Daily Firewall Change Consolidation (%s)" % ctx.report_date.strftime("%d-%b-%Y"),
        [
            "DXC Technology • Built by Ganesh A | Tool v%s | Operator: %s | Overall: %s"
            % (VERSION, ctx.operator or "(not set)", ctx.status),
            "Application & Asset Owner come from RFC sheets (with SMAX fallback); Title, RFC Owner and Expiry come from SMAX.",
        ],
    )
    all_c = collections.Counter(ctx.verdicts[r.uid].status for r in ctx.rules)
    tot_n = len(ctx.rules)
    comp_pct = ("%d%%" % int(round(100.0 * all_c["NO"] / tot_n))) if tot_n else "0%"
    exp_cnt = 0
    for r in ctx.rules:
        _rec = smax_record(ctx.smax, r, ctx.cfg)
        if _rec and expiry_status(_rec.get("expiry"), ctx.report_date) == "EXPIRED":
            exp_cnt += 1
    kpi_hdr = ["Total Rules", "Compliance %", "PIR YES", "PIR NO", "REVIEW", "Risky Rules", "Expired Temp"]
    kpi_vals = [
        tot_n,
        comp_pct,
        all_c["YES"],
        all_c["NO"],
        all_c["REVIEW"],
        sum(1 for r in ctx.rules if ctx.verdicts[r.uid].risky_rule),
        exp_cnt,
    ]
    for ci, (kh, kv) in enumerate(zip(kpi_hdr, kpi_vals), 1):
        ws.put(5, ci, kh, sty(bold=True, fill="1F3864", color="FFFFFF", h="center"))
        ksty = status_sty("YES") if (kh in ("PIR YES", "Expired Temp") and kv) else (status_sty("NO") if kh == "PIR NO" else sty(bold=True, fill="EDF3FC", h="center"))
        ws.put(6, ci, kv, ksty)

    hdr = [
        "Firewall Tab",
        "Rules",
        "Added",
        "Edited",
        "Removed",
        "Risky",
        "PIR YES",
        "PIR NO",
        "REVIEW",
        "N/A",
        "Compliance %",
    ]
    rows, tot = [], collections.Counter()
    for td in ctx.tabs:
        rs = by_tab[td.name]
        c = collections.Counter(ctx.verdicts[r.uid].status for r in rs)
        rk = sum(1 for r in rs if ctx.verdicts[r.uid].risky_rule)
        n_add = sum(1 for r in rs if r.change_type.lower() == "added")
        n_edt = sum(1 for r in rs if r.change_type.lower() == "edited")
        n_rem = sum(1 for r in rs if r.change_type.lower() in ("removed", "deleted"))
        t_pct = ("%d%%" % int(round(100.0 * c["NO"] / len(rs)))) if rs else "-"
        row = [td.name, len(rs), n_add, n_edt, n_rem, rk, c["YES"], c["NO"], c["REVIEW"], c["N/A"], t_pct]
        rows.append(row)
        for k, v in zip(hdr[1:-1], row[1:-1]):
            tot[k] += v
    rows.append(["Total"] + [tot[k] for k in hdr[1:-1]] + [comp_pct])
    last = table(
        ws,
        8,
        hdr,
        rows,
        [22, 9, 9, 9, 10, 9, 10, 10, 10, 8, 13],
        center_cols=range(2, 12),
        freeze=False,
        filt=False,
    )
    for ci in range(1, len(hdr) + 1):
        ws.restyle(last, ci, sty(bold=True, fill="D9E1F2", h="center" if ci > 1 else None))


# === audit workbook (RFC_Audit_Report) ===
IMPL = {
    "NO": "Implemented",
    "YES": "Mismatch",
    "REVIEW": "Pending Review",
    "N/A": "N/A",
}


def _approved(ctx, v, attr):
    real_attr = "ports" if attr == "port" else attr
    out = PortSet() if real_attr == "ports" else IPSet()
    for item in v.lines_used:
        if isinstance(item, tuple) and len(item) >= 2:
            rfc_num, sr_num = item[0], item[1]
            sh = ctx.sheets.get(rfc_num)
            if sh:
                for ln in sh.lines:
                    if ln.sr == sr_num:
                        out = out | getattr(ln, real_attr)
        elif hasattr(item, real_attr):
            out = out | getattr(item, real_attr)
    return out


def _unsheeted(ctx):
    by = collections.defaultdict(list)
    for r in ctx.rules:
        req = effective_rfcs(r, ctx.cfg)
        if req and not any(n in ctx.sheets for n in req):
            by[req[0]].append(r)
    return sorted(by.items())


def overall_status(ctx):
    st = collections.Counter(v.status for v in ctx.verdicts.values())
    if st["YES"]:
        return "ATTENTION REQUIRED"
    if not ctx.sheets or st["REVIEW"]:
        return "INCOMPLETE"
    return "PASS"


def write_audit(ctx, path):
    bk = Book()
    dash = bk.sheet("Executive Dashboard")
    _impl_audit(ctx, bk.sheet("RFC Implementation Audit"))
    _mismatch(ctx, bk.sheet("Port Mismatch Report"))
    _missing(ctx, bk.sheet("Missing Implementation"))
    _dups(ctx, bk.sheet("Duplicate Rules"))
    _pir(ctx, bk.sheet("PIR Verification"))
    _unexpected(ctx, bk.sheet("Unexpected Changes"))
    _rfc_summary(ctx, bk.sheet("RFC Summary"))
    _reviewer_sheet(ctx, bk.sheet("Reviewer Overrides"))
    _checks(ctx, bk.sheet("Checks"))
    _method(ctx, bk.sheet("Method"))
    _dashboard(ctx, dash)
    fw_mode = ctx.cfg.get("compliance_framework", "all")
    if fw_mode != "off":
        sc_rows, _ = compliance_evaluate(ctx, fw_mode)
        cws = bk.sheet("Compliance Mapping")
        title_block(
            cws,
            "Compliance Control Mapping (Advisory — ISO 27001 / PCI DSS / NIST)",
            ["Technical firewall rule mapping only; does not represent full organizational certification."],
        )
        table(
            cws,
            4,
            ["Framework", "Control ID", "Control Area", "Trigger Condition", "Impacted Rules", "Status", "Remediation Guidance"],
            [list(x) for x in sc_rows],
            [24, 18, 26, 30, 14, 12, 48],
            status_cols=(6,),
            center_cols=(5, 6),
        )
    for ws in bk.sheets:
        ws.fit = True
    bk.save(path)
    return path





COMPLIANCE_CONTROLS = [
    {
        "key": "change_ctrl",
        "iso": ("ISO/IEC 27001:2022", "A.8.32", "Change Management", "PIR ISSUE = YES or REVIEW", "Verify approved RFC port sheet matches implemented rule."),
        "pci": ("PCI DSS v4.0.1", "Req 1.2.2", "Formal Change Control", "PIR ISSUE = YES or REVIEW", "Ensure NSC rule changes follow formal change approval."),
        "nist": ("NIST SP 800-53 / 800-41", "CM-3", "Configuration Change Control", "PIR ISSUE = YES or REVIEW", "Validate change authorization and post-implementation review."),
    },
    {
        "key": "boundary",
        "iso": ("ISO/IEC 27001:2022", "A.8.20 / A.8.22", "Network Security & Segregation", "ANY IP, /16+ Subnet, or Risky Port", "Restrict broad CIDRs and high-risk ports (22, 3389, ANY)."),
        "pci": ("PCI DSS v4.0.1", "Req 1.2.1 / 1.3.1", "Restrict Traffic to Necessary", "ANY IP, /16+ Subnet, or Risky Port", "Enforce least-privilege inbound/outbound firewall rules."),
        "nist": ("NIST SP 800-53 / 800-41", "SC-7 / AC-4", "Boundary Protection & Flow Control", "ANY IP, /16+ Subnet, or Risky Port", "Narrow source/destination scope and block risky services."),
    },
    {
        "key": "recert",
        "iso": ("ISO/IEC 27001:2022", "A.5.18", "Access Rights Review", "Expired Temp Access or Disabled Rule", "Decommission expired temporary rules and stale disabled entries."),
        "pci": ("PCI DSS v4.0.1", "Req 1.2.7", "Periodic Rule-Set Review", "Expired Temp Access or Disabled Rule", "Review and remove expired or unneeded NSC rules."),
        "nist": ("NIST SP 800-53 / 800-41", "CM-7", "Least Functionality", "Expired Temp Access or Disabled Rule", "Remove expired temporary firewall exceptions promptly."),
    },
    {
        "key": "doc_owner",
        "iso": ("ISO/IEC 27001:2022", "A.8.15", "Traceability & Logging", "Blank Description or Missing Asset Owner", "Record ticket reference, business owner, and justification."),
        "pci": ("PCI DSS v4.0.1", "Req 1.2.5 / 1.2.6", "Business Justification & Owner", "Blank Description or Missing Asset Owner", "Document business justification, expiry, and owner per rule."),
        "nist": ("NIST SP 800-53 / 800-41", "CM-2 / AU-2", "Baseline & Audit Traceability", "Blank Description or Missing Asset Owner", "Ensure every rule carries complete metadata and ownership."),
    },
]


def compliance_evaluate(ctx, fw_mode="all"):
    mode = (fw_mode or "all").strip().lower()
    if mode == "off":
        return [], {}
    active_fws = (
        ("iso", "pci", "nist")
        if mode == "all"
        else ((mode,) if mode in ("iso", "pci", "nist") else ("iso", "pci", "nist"))
    )
    hits = {c["key"]: [] for c in COMPLIANCE_CONTROLS}
    rule_refs = {}

    for r in ctx.rules:
        v = ctx.verdicts[r.uid]
        rec = smax_record(ctx.smax, r, ctx.cfg)
        exp_val = (rec.get("expiry") or "") if rec is not None else ""
        is_exp = expiry_status(exp_val, ctx.report_date) == "EXPIRED"
        owner_txt = ctx.owners.get(r.uid, ("", ""))[0]

        r_keys = []
        if v.status in ("YES", "REVIEW"):
            hits["change_ctrl"].append(r)
            r_keys.append("change_ctrl")
        if v.risky_rule:
            hits["boundary"].append(r)
            r_keys.append("boundary")
        if is_exp or (r.enabled is False):
            hits["recert"].append(r)
            r_keys.append("recert")
        if (not r.description.strip()) or (not owner_txt.strip()):
            hits["doc_owner"].append(r)
            r_keys.append("doc_owner")

        refs = []
        for k in r_keys:
            cdef = next(x for x in COMPLIANCE_CONTROLS if x["key"] == k)
            for fk in active_fws:
                refs.append("%s %s" % (fk.upper(), cdef[fk][1]))
        rule_refs[r.uid] = ", ".join(refs)

    scorecard = []
    for cdef in COMPLIANCE_CONTROLS:
        cnt = len(hits[cdef["key"]])
        if cnt == 0:
            c_stat = "PASS"
        elif cdef["key"] in ("change_ctrl", "boundary", "recert"):
            c_stat = "FAIL"
        else:
            c_stat = "REVIEW"
        for fk in active_fws:
            fw_name, cid, carea, trig, guide = cdef[fk]
            scorecard.append((fw_name, cid, carea, trig, cnt, c_stat, guide))
    return scorecard, rule_refs




def compliance_hits_map(ctx, fw_mode="all"):
    mode = (fw_mode or "all").strip().lower()
    if mode == "off":
        return {}, {}
    active_fws = (
        ("iso", "pci", "nist")
        if mode == "all"
        else ((mode,) if mode in ("iso", "pci", "nist") else ("iso", "pci", "nist"))
    )
    by_cid = collections.defaultdict(list)
    rule_actions = {}
    for r in ctx.rules:
        v = ctx.verdicts[r.uid]
        rec = smax_record(ctx.smax, r, ctx.cfg)
        exp_val = (rec.get("expiry") or "") if rec is not None else ""
        is_exp = expiry_status(exp_val, ctx.report_date) == "EXPIRED"
        owner_txt = ctx.owners.get(r.uid, ("", ""))[0]

        r_keys, acts = [], []
        if v.status in ("YES", "REVIEW"):
            r_keys.append("change_ctrl")
            acts.append("Verify RFC port sheet vs implemented rule")
        if v.risky_rule:
            r_keys.append("boundary")
            acts.append("Restrict ANY / large CIDR or risky ports")
        if is_exp or (r.enabled is False):
            r_keys.append("recert")
            acts.append("Decommission expired / disabled rule")
        if (not r.description.strip()) or (not owner_txt.strip()):
            r_keys.append("doc_owner")
            acts.append("Update missing Description / Asset Owner")

        rule_actions[r.uid] = "; ".join(acts)
        for k in r_keys:
            cdef = next(x for x in COMPLIANCE_CONTROLS if x["key"] == k)
            for fk in active_fws:
                cid = cdef[fk][1]
                by_cid[(cdef[fk][0], cid)].append(r)
    return by_cid, rule_actions


def export_compliance_xlsx(ctx, path, fw_mode="all"):
    scorecard, rule_refs = compliance_evaluate(ctx, fw_mode)
    bk = Book()
    ws1 = bk.sheet("Control Scorecard")
    title_block(
        ws1,
        "DXC Technology — Compliance Control Mapping (Advisory)",
        [
            "DXC Technology • Built by Ganesh A | Report Date: %s | Mode: %s | Advisory Technical Control Mapping"
            % (ctx.report_date.strftime("%d-%b-%Y"), fw_mode.upper()),
        ],
    )
    table(
        ws1,
        4,
        ["Framework", "Control ID", "Control Area", "Trigger Condition", "Impacted Rules", "Status", "Remediation Guidance"],
        [list(r) for r in scorecard],
        [24, 18, 26, 30, 14, 12, 48],
        status_cols=(6,),
        center_cols=(5, 6),
    )
    ws1.fit = True

    ws2 = bk.sheet("Impacted Rules")
    title_block(
        ws2,
        "Rules Triggering Mapped Compliance Controls",
        ["Shows only rules with 1 or more mapped control findings."],
    )
    imp_rows = []
    for r in ctx.rules:
        cref = rule_refs.get(r.uid, "")
        if not cref:
            continue
        v = ctx.verdicts[r.uid]
        imp_rows.append([
            r.tab,
            r.name,
            ", ".join("RFC" + n for n in r.chain),
            v.status,
            ", ".join(v.risky_ports),
            cref,
            v.detail,
        ])
    table(
        ws2,
        4,
        ["Firewall Tab", "Rule Name", "RFC Match", "PIR ISSUE", "Risky", "Mapped Control Ref", "Detail"],
        imp_rows,
        [14, 24, 18, 12, 16, 40, 44],
        status_cols=(4,),
        center_cols=(4,),
    )
    ws2.fit = True
    bk.save(path)
    return path




def export_compliance_html(ctx, path, fw_mode="all"):
    import html
    scorecard, rule_refs = compliance_evaluate(ctx, fw_mode)
    _, rule_actions = compliance_hits_map(ctx, fw_mode)
    tot_c = len(scorecard)
    pass_c = sum(1 for r in scorecard if r[5] == "PASS")
    fail_c = sum(1 for r in scorecard if r[5] == "FAIL")
    score_pct = int(round(100.0 * pass_c / tot_c)) if tot_c else 0
    sc_rows_html = "".join(
        "<tr><td>%s</td><td><b>%s</b></td><td>%s</td><td>%s</td><td style=\"text-align:center\">%s</td>"
        "<td><span class=\"badge %s\">%s</span></td><td>%s</td></tr>"
        % (
            html.escape(str(r[0])), html.escape(str(r[1])), html.escape(str(r[2])),
            html.escape(str(r[3])), r[4],
            "b-no" if r[5] == "PASS" else ("b-yes" if r[5] == "FAIL" else "b-rev"),
            html.escape(str(r[5])), html.escape(str(r[6])),
        )
        for r in scorecard
    )
    imp_html = []
    for r in ctx.rules:
        cref = rule_refs.get(r.uid, "")
        if not cref:
            continue
        v = ctx.verdicts[r.uid]
        imp_html.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            % (
                html.escape(r.tab), html.escape(r.name),
                html.escape(", ".join("RFC" + n for n in r.chain)),
                html.escape(v.status), html.escape(cref),
                html.escape(rule_actions.get(r.uid, "")), html.escape(ctx.owners[r.uid][0]),
            )
        )
    body_html = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>DXC Compliance Brief</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#F0F4FA;color:#0B1930;margin:0;padding:24px;}
.hdr{background:#0B1930;color:#fff;padding:20px 26px;border-radius:10px 10px 0 0;border-bottom:5px solid #FF6B35;}
.hdr h1{margin:0;font-size:21px;}.hdr p{margin:6px 0 0;color:#93C5FD;font-size:13px;}
.card{background:#fff;padding:20px 26px;border-radius:0 0 10px 10px;box-shadow:0 4px 16px rgba(11,25,48,.08);}
.kpis{display:flex;gap:12px;margin:14px 0 20px;flex-wrap:wrap;}
.kpi{flex:1;min-width:140px;background:#F4F8FE;border-top:4px solid #2563EB;border-radius:6px;padding:10px 14px;}
.kpi .v{font-size:24px;font-weight:700;}.kpi .l{font-size:11px;color:#475569;text-transform:uppercase;}
table{width:100%%;border-collapse:collapse;font-size:12px;margin-top:10px;margin-bottom:20px;}
th{background:#1E3A8A;color:#fff;padding:8px;text-align:left;}
td{padding:7px 8px;border-bottom:1px solid #E2E8F0;vertical-align:top;}
.badge{padding:2px 8px;border-radius:4px;font-weight:700;font-size:11px;}
.b-yes{background:#FEE2E2;color:#B91C1C;}.b-no{background:#DCFCE7;color:#15803D;}.b-rev{background:#FEF3C7;color:#B45309;}
.foot{margin-top:16px;font-size:11px;color:#64748B;}
</style></head><body>
<div class="hdr"><h1>DXC Technology — Compliance Control Mapping Brief (Advisory)</h1>
<p>Report Date: %s &nbsp;|&nbsp; Framework Mode: %s &nbsp;|&nbsp; Operator: %s</p></div>
<div class="card">
<div class="kpis">
<div class="kpi"><div class="l">Controls Evaluated</div><div class="v">%d</div></div>
<div class="kpi" style="border-color:#16A34A"><div class="l">Passing Controls</div><div class="v" style="color:#16A34A">%d</div></div>
<div class="kpi" style="border-color:#DC2626"><div class="l">Failed Controls</div><div class="v" style="color:#DC2626">%d</div></div>
<div class="kpi" style="border-color:#FF6B35"><div class="l">Control Score</div><div class="v" style="color:#FF6B35">%d%%</div></div>
</div>
<h3>Control Scorecard</h3>
<table><tr><th>Framework</th><th>Control ID</th><th>Control Area</th><th>Trigger</th><th>Impacted</th><th>Status</th><th>Guidance</th></tr>%s</table>
<h3>Impacted Rules (%d)</h3>
<table><tr><th>Tab</th><th>Rule Name</th><th>RFC</th><th>PIR</th><th>Mapped Controls</th><th>Recommended Action</th><th>Asset Owner</th></tr>%s</table>
<div class="foot">DXC Technology • Built by Ganesh A &nbsp;|&nbsp; Advisory technical control mapping only; does not replace full organizational certification.</div>
</div></body></html>""" % (
        html.escape(ctx.report_date.strftime("%d-%b-%Y")),
        html.escape(fw_mode.upper()),
        html.escape(ctx.operator or "Not Set"),
        tot_c, pass_c, fail_c, score_pct,
        sc_rows_html, len(imp_html), "".join(imp_html),
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(body_html)
    return path


def export_compliance_json(ctx, path, fw_mode="all"):
    scorecard, rule_refs = compliance_evaluate(ctx, fw_mode)
    _, rule_actions = compliance_hits_map(ctx, fw_mode)
    payload = {
        "tool": "PolicyPulse — DXC Firewall Change Audit Console",
        "version": VERSION,
        "config_hash": ctx.config_hash,
        "report_date": ctx.report_date.strftime("%Y-%m-%d"),
        "operator": ctx.operator,
        "framework_mode": fw_mode,
        "advisory_note": "Technical firewall rule mapping only.",
        "audit_scope_note": "PIR ISSUE = NO indicates rule configuration matches the RFC port sheet; live-traffic PIR evidence is not independently assessed.",
        "firewall_coverage": {
            "received": ctx.coverage_summary[0],
            "expected": ctx.coverage_summary[1],
            "missing_tabs": ctx.coverage_summary[2],
        },
        "report_windows": ctx.report_windows,
        "chain_of_custody": {
            "inputs": ctx.input_custody,
            "outputs": ctx.output_custody,
        },
        "scorecard": [
            {
                "framework": r[0], "control_id": r[1], "control_area": r[2],
                "trigger": r[3], "impacted_rules": r[4], "status": r[5], "guidance": r[6],
            }
            for r in scorecard
        ],
        "impacted_rules": [
            {
                "tab": r.tab, "rule_name": r.name,
                "rfcs": ["RFC" + n for n in r.chain],
                "source": r.src.summary(5) if r.src else "",
                "destination": r.dst.summary(5) if r.dst else "",
                "service": r.ports.fmt() or ", ".join(r.svc_tokens),
                "pir_issue": ctx.verdicts[r.uid].status,
                "risky_ports": ctx.verdicts[r.uid].risky_ports,
                "asset_owner": ctx.owners[r.uid][0],
                "mapped_controls": rule_refs[r.uid],
                "recommended_action": rule_actions.get(r.uid, ""),
            }
            for r in ctx.rules if rule_refs.get(r.uid)
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    return path




def export_expiry_cleanup_xlsx(ctx, path):
    by_owner = collections.defaultdict(list)
    detail_rows = []
    for r in ctx.rules:
        rec = smax_record(ctx.smax, r, ctx.cfg)
        if rec is None:
            continue
        exp_val = rec.get("expiry") or ""
        est = expiry_status(exp_val, ctx.report_date)
        if not (est == "EXPIRED" or est.startswith("EXPIRING SOON")):
            continue
        owner = (rec.get("rfc_owner") or "").strip() or ctx.owners.get(r.uid, ("", ""))[0] or "(Unassigned)"
        exp_str = exp_val.strftime("%d-%b-%Y") if isinstance(exp_val, (datetime.date, datetime.datetime)) else clean(exp_val)
        rfcs = ", ".join("RFC" + n for n in r.chain)
        by_owner[owner].append((est, r.tab, rfcs))
        detail_rows.append((
            0 if est == "EXPIRED" else 1,
            owner.lower(),
            [
                owner,
                est,
                exp_str,
                r.tab,
                r.name,
                rfcs,
                r.src.summary(3) if r.src else "",
                r.dst.summary(3) if r.dst else "",
                r.ports.fmt() or ", ".join(r.svc_tokens),
                ctx.owners.get(r.uid, ("", ""))[0],
                clean(rec.get("title") or ""),
            ],
        ))
    detail_rows.sort(key=lambda x: (x[0], x[1]))
    sum_rows = []
    for owner, items in sorted(by_owner.items(), key=lambda kv: (-sum(1 for e, _, _ in kv[1] if e == "EXPIRED"), kv[0].lower())):
        n_exp = sum(1 for e, _, _ in items if e == "EXPIRED")
        n_soon = len(items) - n_exp
        rfcs = ", ".join(sorted(set(rf for _, _, rf in items if rf)))
        tabs = ", ".join(sorted(set(tb for _, tb, _ in items if tb)))
        sum_rows.append([owner, n_exp, n_soon, len(items), rfcs, tabs])

    bk = Book()
    ws1 = bk.sheet("Owner Summary")
    title_block(
        ws1,
        "DXC Technology — Owner-Grouped Expiry & Cleanup Summary",
        [
            "DXC Technology • Built by Ganesh A | Report Date: %s | Expired / Expiring Soon Temporary Rules"
            % ctx.report_date.strftime("%d-%b-%Y"),
        ],
    )
    table(
        ws1,
        4,
        ["RFC Owner", "Expired", "Expiring Soon", "Total Action Needed", "Affected RFCs", "Firewall Tabs"],
        sum_rows or [["(No expired or expiring temporary rules found)", 0, 0, 0, "", ""]],
        [30, 12, 14, 18, 34, 28],
        center_cols=(2, 3, 4),
    )
    ws1.fit = True

    ws2 = bk.sheet("Cleanup Rule Detail")
    title_block(
        ws2,
        "Expired & Expiring Temporary Rules — Detail for Decommissioning",
        ["Sorted with EXPIRED rules first, grouped by RFC Owner."],
    )
    table(
        ws2,
        4,
        ["RFC Owner", "Expiry Status", "Expiry Date", "Firewall Tab", "Rule Name", "RFC Match", "Source", "Destination", "Service", "Asset Owner", "SMAX Title"],
        [x[2] for x in detail_rows] or [["(None)", "", "", "", "", "", "", "", "", "", ""]],
        [28, 20, 14, 14, 24, 16, 26, 26, 20, 22, 32],
        center_cols=(2, 3),
    )
    for ri, (_, _, row_vals) in enumerate(detail_rows, 5):
        ws2.restyle(ri, 2, status_sty("YES") if row_vals[1] == "EXPIRED" else YELLOW)
    ws2.fit = True
    bk.save(path)
    return path


def export_html_summary(ctx, path):
    st = collections.Counter(ctx.verdicts[r.uid].status for r in ctx.rules)
    risky_n = sum(1 for r in ctx.rules if ctx.verdicts[r.uid].risky_rule)
    exp_n = 0
    for r in ctx.rules:
        rec = smax_record(ctx.smax, r, ctx.cfg)
        if rec and expiry_status(rec.get("expiry"), ctx.report_date) == "EXPIRED":
            exp_n += 1
    by_fw = collections.OrderedDict((td.name, []) for td in ctx.tabs)
    for r in ctx.rules:
        by_fw[r.tab].append(r)
    fw_rows_html = []
    for fname, frs in by_fw.items():
        if not frs:
            continue
        fs = collections.Counter(ctx.verdicts[x.uid].status for x in frs)
        frsk = sum(1 for x in frs if ctx.verdicts[x.uid].risky_rule)
        fw_rows_html.append(
            "<tr><td><b>%s</b></td><td>%d</td><td style='color:#9C0006;font-weight:bold'>%d</td>"
            "<td style='color:#006100;font-weight:bold'>%d</td><td>%d</td><td>%d</td></tr>"
            % (_xesc(fname), len(frs), fs["YES"], fs["NO"], fs["REVIEW"], frsk)
        )
    exc_rows = []
    for r in ctx.rules:
        v = ctx.verdicts[r.uid]
        if v.status in ("YES", "REVIEW"):
            exc_rows.append(
                "<tr><td>%s</td><td>%s</td><td>%s</td><td><b>%s</b></td><td>%s</td><td>%s</td></tr>"
                % (
                    _xesc(r.tab),
                    _xesc(r.name),
                    _xesc(", ".join("RFC" + n for n in r.chain)),
                    _xesc(v.status),
                    _xesc(", ".join(v.risky_ports)),
                    _xesc(v.detail),
                )
            )
    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DXC Technology - Firewall Audit Executive Summary</title>
<style>
  body { font-family: Arial, sans-serif; background: #EDF3FC; color: #0F2547; margin: 0; padding: 24px; }
  .wrap { max-width: 1080px; margin: auto; background: #FFFFFF; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 18px rgba(15,37,71,0.12); }
  .hdr { background: #0F2547; color: #FFFFFF; padding: 20px 28px; border-bottom: 6px solid #FF6B35; }
  .hdr h1 { margin: 0 0 4px 0; font-size: 22px; }
  .hdr p { margin: 0; color: #D8E6FB; font-size: 13px; }
  .kpis { display: flex; gap: 12px; padding: 20px 28px; flex-wrap: wrap; }
  .kpi { flex: 1; min-width: 140px; padding: 14px; border-radius: 8px; border: 1px solid #D8E6FB; }
  .kpi .lbl { font-size: 11px; font-weight: bold; text-transform: uppercase; }
  .kpi .val { font-size: 26px; font-weight: bold; margin-top: 4px; }
  .sec { padding: 8px 28px 24px 28px; }
  h2 { font-size: 16px; color: #1E40AF; border-bottom: 2px solid #D8E6FB; padding-bottom: 6px; }
  table { width: 100%%; border-collapse: collapse; font-size: 13px; margin-top: 10px; }
  th { background: #1E40AF; color: #FFFFFF; text-align: left; padding: 8px 10px; }
  td { border-bottom: 1px solid #E5E7EB; padding: 8px 10px; vertical-align: top; }
  .ftr { background: #0F2547; color: #D8E6FB; font-size: 12px; padding: 12px 28px; }
</style>
</head>
<body>
<div class="wrap">
  <div class="hdr">
    <h1>DXC Technology — Firewall Change Audit Executive Summary</h1>
    <p>Report Date: %s &nbsp;|&nbsp; Operator: %s &nbsp;|&nbsp; Overall Status: <b>%s</b></p>
  </div>
  <div class="kpis">
    <div class="kpi" style="background:#DCEAFE;color:#1E40AF;"><div class="lbl">Rules Audited</div><div class="val">%d</div></div>
    <div class="kpi" style="background:#FFC7CE;color:#9C0006;"><div class="lbl">PIR ISSUE = YES</div><div class="val">%d</div></div>
    <div class="kpi" style="background:#C6EFCE;color:#006100;"><div class="lbl">PIR ISSUE = NO</div><div class="val">%d</div></div>
    <div class="kpi" style="background:#FFEB9C;color:#9C5700;"><div class="lbl">REVIEW</div><div class="val">%d</div></div>
    <div class="kpi" style="background:#FCE4D6;color:#9C0006;"><div class="lbl">Risky / Expired</div><div class="val">%d / %d</div></div>
  </div>
  <div class="sec">
    <h2>Per-Firewall Breakdown</h2>
    <table><tr><th>Firewall Tab</th><th>Rules</th><th>PIR YES</th><th>PIR NO</th><th>REVIEW</th><th>Risky</th></tr>%s</table>
  </div>
  <div class="sec">
    <h2>Exceptions &amp; Items Requiring Review (%d)</h2>
    <table><tr><th>Tab</th><th>Rule Name</th><th>RFC</th><th>PIR ISSUE</th><th>Risky</th><th>Detail</th></tr>%s</table>
  </div>
  <div class="ftr">DXC Technology &bull; Built by Ganesh A &nbsp;|&nbsp; Offline Firewall Change Audit Tool v%s</div>
</div>
</body>
</html>""" % (
        ctx.report_date.strftime("%d-%b-%Y"),
        _xesc(ctx.operator or "(not set)"),
        _xesc(ctx.status),
        len(ctx.rules),
        st["YES"],
        st["NO"],
        st["REVIEW"],
        risky_n,
        exp_n,
        "".join(fw_rows_html),
        len(exc_rows),
        "".join(exc_rows) or "<tr><td colspan='6'>No exceptions found.</td></tr>",
        VERSION,
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


def _rfcs(nums):
    return ", ".join("RFC" + n for n in nums)


def _impl_audit(ctx, ws):
    title_block(
        ws, "RFC Implementation Audit — Rule-Level Verification"
    )
    hdr = [
        "Tab",
        "Row in tab",
        "Firewall",
        "Row in file",
        "Change type",
        "Rule name",
        "RFC number(s)",
        "RFC sheet used",
        "Rule source",
        "Rule destination",
        "Services (as exported)",
        "Ports resolved",
        "Implementation status",
        "PIR ISSUE",
        "Reason / detail",
        "Merged-rule note",
        "RFC lines matched",
        "Source file (AlgoSec)",
        "Tool verdict (before review)",
        "Confidence",
        "Confidence notes",
        "Override reason",
        "Override comment",
        "Reviewed / approved by",
    ]
    rows = []
    for r in ctx.rules:
        v = ctx.verdicts[r.uid]
        ov = v.override or {}
        rows.append(
            [
                r.tab,
                r.tab_row,
                r.cons.report.device,
                r.file_row,
                r.change_type,
                r.name,
                _rfcs(r.chain),
                _rfcs(v.rfc_used),
                r.src.summary(5) if r.src else "",
                r.dst.summary(5) if r.dst else "",
                ", ".join(r.svc_tokens),
                r.ports.fmt(),
                IMPL[v.status],
                v.status,
                v.detail
                + ((" " + " ".join(v.notes)) if v.notes else ""),
                v.merged_note,
                fmt_lines(v.lines_used),
                r.file,
                v.tool_status or v.status,
                v.confidence,
                v.confidence_why,
                ov.get("reason", ""),
                ov.get("comment", ""),
                " / ".join(x for x in (ov.get("by", ""), ov.get("approved_by", "")) if x),
            ]
        )
    table(
        ws,
        3,
        hdr,
        rows,
        [
            10,
            8,
            22,
            8,
            9,
            26,
            22,
            20,
            34,
            34,
            28,
            26,
            20,
            10,
            60,
            44,
            28,
            70,
            14,
            12,
            50,
            30,
            40,
            24,
        ],
        status_cols=(13, 14, 19),
        center_cols=(1, 2, 4, 5),
    )


def _mismatch(ctx, ws):
    title_block(
        ws,
        "Port mismatch report: what in each rule is not approved by"
        " its RFC",
        [
            "One row per mismatching item. Informational rows (merged"
            " rules) do not change PIR ISSUE."
        ],
    )
    hdr = [
        "Tab",
        "Row in tab",
        "Rule name",
        "RFC",
        "Category",
        "Dimension",
        "In the rule but not approved",
        "What the RFC lines approve",
        "RFC lines compared",
        "Reason",
    ]
    rows = []
    for r in ctx.rules:
        v = ctx.verdicts[r.uid]
        base = [r.tab, r.tab_row, r.name, _rfcs(v.rfc_used)]
        lines = (
            fmt_lines(v.lines_used)
            or "no line shares a port with the rule"
        )
        if v.status == "YES":
            if v.ex_src:
                rows.append(
                    base
                    + [
                        "Mismatch",
                        "Source",
                        v.ex_src.summary(8),
                        _approved(ctx, v, "src").summary(8),
                        lines,
                        (
                            "Source address not requested for these"
                            " ports in the RFC."
                        ),
                    ]
                )
            if v.ex_dst:
                rows.append(
                    base
                    + [
                        "Mismatch",
                        "Destination",
                        v.ex_dst.summary(8),
                        _approved(ctx, v, "dst").summary(8),
                        lines,
                        (
                            "Destination address not requested for"
                            " these ports in the RFC."
                        ),
                    ]
                )
            if v.ex_ports:
                rows.append(
                    base
                    + [
                        "Mismatch",
                        "Port / service",
                        (
                            "ANY (all ports)"
                            if r.any_service
                            else v.ex_ports.fmt()
                        ),
                        _approved(ctx, v, "port").fmt() or "(none)",
                        lines,
                        "Port or service not requested in the RFC.",
                    ]
                )
            if not (v.ex_src or v.ex_dst or v.ex_ports):
                rows.append(
                    base
                    + [
                        "Mismatch",
                        "Merged rule",
                        v.merged_note,
                        "",
                        lines,
                        v.detail,
                    ]
                )
        elif v.merged_note:
            rows.append(
                base
                + [
                    "Informational",
                    "Merged rule",
                    v.merged_note,
                    "",
                    lines,
                    (
                        "Each source, destination and port is approved,"
                        " but together the rule allows combinations no"
                        " single RFC line approves."
                    ),
                ]
            )
    table(
        ws,
        4,
        hdr,
        rows,
        [10, 8, 26, 18, 13, 14, 46, 46, 30, 50],
        center_cols=(1, 2, 5),
    )
    for ri in range(5, 5 + len(rows)):
        ws.restyle(
            ri,
            5,
            status_sty(
                "YES" if ws.val(ri, 5) == "Mismatch" else "REVIEW"
            ),
        )


def _missing(ctx, ws):
    title_block(
        ws,
        "Missing implementation: RFC lines not (fully) found in the"
        " rules provided",
        [
            "Judged only on the AlgoSec reports supplied. A line may be"
            " implemented on another day or firewall."
        ],
    )
    hdr = [
        "RFC",
        "RFC sheet file",
        "Sr. No.",
        "Row in RFC sheet",
        "Source IPs",
        "Destination IPs",
        "Ports",
        "Status",
        "What is missing",
        "Rules carrying this RFC (tab, row)",
    ]
    rows = []
    for res in ctx.rfc_results:
        carry = ", ".join(
            "%s r%s" % (r.tab, r.tab_row)
            for r in res.rules
            if not r.removed
        )
        for c in res.coverage:
            if c.status != "Covered":
                ln = c.line
                rows.append(
                    [
                        "RFC" + res.number,
                        res.sheet.filename,
                        ln.sr,
                        ln.row,
                        ln.src.summary(6),
                        ln.dst.summary(6),
                        ln.ports.fmt(),
                        c.status,
                        c.detail,
                        carry or "(none)",
                    ]
                )
    table(
        ws,
        4,
        hdr,
        rows,
        [14, 22, 7, 9, 38, 38, 22, 16, 56, 34],
        status_cols=(8,),
        center_cols=(1, 3, 4),
    )


def _dups(ctx, ws):
    title_block(
        ws,
        "Duplicate rules: same tab, same source, destination, service,"
        " action and zones",
    )
    hdr = [
        "Group",
        "Tab",
        "Row in tab",
        "Rule name",
        "Change type",
        "RFC number(s)",
        "Source",
        "Destination",
        "Services",
        "Action",
        "Note",
    ]
    rows = []
    for gi, g in enumerate(ctx.duplicates, 1):
        for r in g:
            rows.append(
                [
                    "D%d" % gi,
                    r.tab,
                    r.tab_row,
                    r.name,
                    r.change_type,
                    _rfcs(r.chain),
                    r.src.summary(4),
                    r.dst.summary(4),
                    r.ports.fmt(),
                    r.action,
                    "Same flow appears %d times in this tab." % len(g),
                ]
            )
    table(
        ws,
        3,
        hdr,
        rows,
        [8, 10, 8, 28, 10, 24, 36, 36, 26, 9, 34],
        center_cols=(1, 2, 3, 5),
    )
    if not rows:
        ws.put(5, 1, "No duplicate rules found.", SUB)


def _pir(ctx, ws):
    title_block(
        ws,
        "Post-Implementation Review (PIR) Verification Summary",
        [
            "Verified = every RFC line is implemented and no rule"
            " deviates. The configuration check cannot prove"
            " post-implementation testing; that evidence is not in the"
            " inputs."
        ],
    )
    hdr = [
        "RFC",
        "RFC sheet file",
        "RFC date",
        "Lines",
        "Lines covered",
        "Rules carrying RFC",
        "PIR YES",
        "PIR NO",
        "REVIEW",
        "Implementation status",
        "PIR status",
        "Notes",
    ]
    rows = []
    for res in ctx.rfc_results:
        covered = sum(1 for c in res.coverage if c.status == "Covered")
        rows.append(
            [
                "RFC" + res.number,
                res.sheet.filename,
                res.sheet.date,
                len(res.coverage),
                covered,
                len(res.rules),
                res.counts["YES"],
                res.counts["NO"],
                res.counts["REVIEW"],
                res.impl,
                res.pir,
                " ".join(list(res.notes) + list(res.sheet.warnings)),
            ]
        )
    for n, rs in _unsheeted(ctx):
        rows.append(
            [
                "RFC" + n,
                "(not provided)",
                None,
                "",
                "",
                len(rs),
                "",
                "",
                len(rs),
                "Unable to Verify",
                "PIR Evidence Missing",
                "Port sheet for this RFC is needed. Used by: "
                + ", ".join(
                    "%s r%s" % (r.tab, r.tab_row) for r in rs[:8]
                )
                + (" ..." if len(rs) > 8 else ""),
            ]
        )
    table(
        ws,
        4,
        hdr,
        rows,
        [14, 24, 12, 7, 9, 10, 8, 8, 8, 22, 22, 60],
        status_cols=(10, 11),
        center_cols=(1, 3, 4, 5, 6, 7, 8, 9),
    )


def _unexpected(ctx, ws):
    title_block(
        ws,
        "Unexpected Changes — Untraceable or Out-of-Scope Rules",
        [
            "Changes with no traceable RFC, rules unrelated to their"
            " RFC, and changes this tool does not audit."
        ],
    )
    hdr = [
        "Category",
        "Tab / file",
        "Row",
        "Rule name",
        "Change type",
        "Changed by",
        "Change time",
        "Why it is listed",
    ]
    rows = []
    for r, cat, why in ctx.unexpected:
        cb = ""
        for h, val in zip(ctx.tab_headers.get(r.tab, []), r.values):
            if h.strip().lower() == "changed by":
                cb = str(val or "").strip()
        rows.append(
            [
                cat,
                r.tab,
                r.tab_row,
                r.name,
                r.change_type,
                cb,
                r.time_text,
                why,
            ]
        )
    for rep in ctx.reports:
        extra = []
        for key, label in (
            ("nat", "NAT rule change(s)"),
            ("objects", "policy-object change(s)"),
            ("topology", "topology change(s)"),
            ("risks", "risk entry(ies)"),
        ):
            if rep.counts.get(key):
                extra.append("%d %s" % (rep.counts[key], label))
        if extra:
            rows.append(
                [
                    "Not audited",
                    rep.filename,
                    "",
                    "",
                    "",
                    "",
                    "",
                    "Report also lists "
                    + ", ".join(extra)
                    + ". These are outside the RFC port-sheet check;"
                    " review them in the AlgoSec report.",
                ]
            )
    table(
        ws,
        4,
        hdr,
        rows,
        [16, 30, 7, 28, 10, 14, 20, 70],
        center_cols=(3, 5),
    )
    for ri in range(5, 5 + len(rows)):
        ws.restyle(
            ri,
            1,
            status_sty(
                "YES"
                if ws.val(ri, 1) in ("No RFC number", "Not in the RFC")
                else "REVIEW"
            ),
        )


def _rfc_summary(ctx, ws):
    title_block(
        ws,
        "RFC summary: every RFC number seen in the rules or supplied as"
        " a port sheet",
    )
    hdr = [
        "RFC",
        "Port sheet provided",
        "Port sheet file",
        "Rules carrying RFC",
        "Tabs",
        "PIR YES",
        "PIR NO",
        "REVIEW",
        "Implementation status",
        "PIR status",
    ]
    by = collections.OrderedDict()
    for r in ctx.rules:
        for n in r.chain:
            by.setdefault(n, []).append(r)
    res = dict((x.number, x) for x in ctx.rfc_results)
    for n in ctx.sheets:
        by.setdefault(n, [])
    rows = []
    for n in sorted(by):
        rs = by[n]
        st = collections.Counter(ctx.verdicts[r.uid].status for r in rs)
        x = res.get(n)
        rows.append(
            [
                "RFC" + n,
                "Yes" if x else "No",
                x.sheet.filename if x else "",
                len(rs),
                ", ".join(sorted(set(r.tab for r in rs))),
                st["YES"],
                st["NO"],
                st["REVIEW"],
                x.impl if x else "Unable to Verify",
                x.pir if x else "PIR Evidence Missing",
            ]
        )
    table(
        ws,
        3,
        hdr,
        rows,
        [14, 10, 24, 10, 26, 8, 8, 8, 22, 22],
        status_cols=(9, 10),
        center_cols=(1, 2, 4, 6, 7, 8),
    )


def _checks(ctx, ws):
    title_block(ws, "Data Integrity & Input Verification Checks")
    r = 3
    ws.put(r, 1, "AlgoSec reports", BOLD)
    hdr = [
        "File",
        "Device",
        "Layout",
        "Rules",
        "NAT rows",
        "Object changes",
        "Topology",
        "Risks",
        "GENERAL total",
        "Rows counted",
        "Checksum",
    ]
    rows = [
        [
            rep.filename,
            rep.device,
            rep.layout,
            len(rep.rows),
            len(rep.nat_rows),
            rep.counts.get("objects", 0),
            rep.counts.get("topology", 0),
            rep.counts.get("risks", 0),
            rep.declared_total,
            rep.counts.get("computed_total"),
            (
                "OK"
                if rep.checksum_ok
                else ("MISMATCH" if rep.checksum_ok is False else "n/a")
            ),
        ]
        for rep in ctx.reports
    ]
    r = (
        table(
            ws,
            r + 1,
            hdr,
            rows,
            [46, 26, 9, 9, 10, 14, 10, 8, 14, 13, 12],
            status_cols=(11,),
            center_cols=range(3, 12),
            freeze=False,
            filt=False,
        )
        + 2
    )
    ws.put(r, 1, "Consolidation (HA rule)", BOLD)
    rows = [
        [
            td.name,
            ", ".join(rep.device for rep in td.reports) or "(no file)",
            len(td.rows),
            td.ha_stats["mirrors_dropped"],
            td.ha_stats["kept_differs"],
            td.ha_stats["kept_only_partner"],
        ]
        for td in ctx.tabs
    ]
    r = (
        table(
            ws,
            r + 1,
            [
                "Tab",
                "Files",
                "Rows kept",
                "Mirror rows dropped",
                "Partner rows kept (differ)",
                "Partner rows kept (only on partner)",
            ],
            rows,
            None,
            center_cols=(3, 4, 5, 6),
            freeze=False,
            filt=False,
        )
        + 2
    )
    rec_n, exp_n, miss_tabs = ctx.coverage_summary
    cov_msg = "%d of %d expected firewall tab(s) received reports%s" % (
        rec_n,
        exp_n,
        ("; missing: " + ", ".join(miss_tabs)) if miss_tabs else " (100% coverage)",
    )
    ws.put(r, 1, "Chain of Custody & Governance Evidence", BOLD)
    ws.put(r + 1, 1, "Tool v%s | Config Hash: %s | %s" % (VERSION, ctx.config_hash, cov_msg), NORM)
    cust_rows = [
        [c["role"], c["name"], c["sha256"], c["size_bytes"], c["mtime"]]
        for c in (ctx.input_custody or [])
    ]
    if cust_rows:
        r = (
            table(
                ws,
                r + 2,
                ["Role", "File", "SHA-256", "Size (bytes)", "Modified"],
                cust_rows,
                [14, 46, 66, 14, 20],
                center_cols=(1, 4),
                freeze=False,
                filt=False,
            )
            + 2
        )
    else:
        r += 3
    ws.put(r, 1, "RFC port sheets", BOLD)
    rows = [
        [
            "RFC" + s.number,
            s.filename,
            s.sheet,
            s.date,
            len(s.lines),
            s.change_kind,
            " ".join(s.warnings),
        ]
        for s in sorted(ctx.sheets.values(), key=lambda s: s.number)
    ]
    r = (
        table(
            ws,
            r + 1,
            [
                "RFC",
                "File",
                "Worksheet",
                "Date on sheet",
                "Lines read",
                "Request type",
                "Parse notes",
            ],
            rows,
            None,
            center_cols=(4, 5),
            freeze=False,
            filt=False,
        )
        + 2
    )
    ws.put(r, 1, "Warnings and problems", BOLD)
    msgs = list(ctx.warnings) + [
        ("WARN", "RFC file %s: %s" % p) for p in ctx.sheet_problems
    ]
    for td in ctx.tabs:
        msgs += [("WARN", w) for w in td.warnings]
    for rep in ctx.reports:
        msgs += [
            ("WARN", "%s: %s" % (rep.filename, w)) for w in rep.warnings
        ]
    for i, (sev, m) in enumerate(
        msgs or [("INFO", "No warnings.")], r + 1
    ):
        ws.put(i, 1, sev, status_sty(sev) or CENTER)
        ws.put(i, 2, m)
        ws.merge(i, 2, i, 8)
        ws.heights[i] = 30 if len(m) > 110 else 16
    ws.widths[1] = 46


def _method(ctx, ws):
    title_block(ws, "Audit Methodology & Policy Assumptions")
    p = ctx.cfg["policy"]
    lines = [
        (
            "Inputs",
            (
                "AlgoSec Changes Summary reports and RFC port sheets,"
                " read-only. No network, no AI; same input gives same"
                " output."
            ),
        ),
        (
            "RFC number",
            (
                "9 digits in the rule name (RFC255862839,"
                " RFC_255862839_1, RFC255862839-1 ...). A short suffix"
                " is the rule sequence, not an RFC line number."
            ),
        ),
        (
            "PIR ISSUE = YES",
            (
                "A source IP, destination IP or port of the rule is not"
                " approved by the RFC lines sharing one of its ports."
            ),
        ),
        (
            "PIR ISSUE = NO",
            (
                "Source, destination and ports are all "
                "approved by the RFC port sheet."
            ),
        ),
        (
            "REVIEW",
            (
                "Cannot decide: no RFC sheet, no RFC number, or a"
                " service/address name that has no port or IP. Never"
                " counted as NO."
            ),
        ),
        (
            "Policies",
            "merged_rule=%s, edited_scope=%s, multi_rfc=%s "
            "(see CONFIG)."
            % (p["merged_rule"], p["edited_scope"], p["multi_rfc"]),
        ),
        (
            "Direction",
            (
                "Blank or Uni-directional: only source to "
                "destination. Bi-directional also approves the reverse."
            ),
        ),
        (
            "Services",
            (
                "AlgoSec gives service names only. Ports are read from"
                " names like TCP_443, 443-tcp, https. Names such as"
                " application-default cannot be resolved and give"
                " REVIEW."
            ),
        ),
        (
            "Asset Owner",
            (
                "Read from the RFC port sheets: Source Owner and Dest."
                " Server Owner of the RFC lines that match the rule's"
                " addresses (all lines of the RFC when none matches)."
                " The same person on both sides is shown once. Blank"
                " when the sheet gives none; SMAX is used only then."
            ),
        ),
        (
            "HA pair",
            (
                "All rows of the primary firewall plus partner rows"
                " that differ (a mirror has same name and identical"
                " content)."
            ),
        ),
        (
            "Not checked",
            (
                "NAT rules and policy-object, topology and risk "
                "entries are not compared with RFC port sheets."
            ),
        ),
        (
            "Traceability",
            (
                "Every row carries its source file and Excel "
                "row; RFC lines are quoted by Sr. No."
            ),
        ),
    ]
    for i, (k, t) in enumerate(lines, 3):
        ws.put(i, 1, k, sty(bold=True))
        ws.put(i, 2, t)
        ws.heights[i] = max(30, 15 * (len(t) // 110 + 1))
    ws.set_widths([24, 120])


def _bar(n, top, width=14):
    return "\u2588" * (int(round(width * n / float(top))) if top else 0)


def _dashboard(ctx, ws):
    status = overall_status(ctx)
    title_block(
        ws,
        "DXC Technology — Firewall Change Audit Executive Dashboard",
        [
            "DXC Technology • Built by Ganesh A | Report date %s | Operator: %s | Run: %s | v%s | %d"
            " AlgoSec file(s), %d RFC sheet(s) | offline"
            % (
                ctx.report_date.strftime("%d-%b-%Y"),
                ctx.operator or "(not set)",
                ctx.run_time,
                VERSION,
                len(ctx.reports),
                len(ctx.sheets),
            )
        ],
    )
    ws.put(4, 1, "Overall audit status", BOLD)
    for c in (2, 3, 4):
        ws.put(4, c, status if c == 2 else None, status_sty(status))
    ws.merge(4, 2, 4, 4)
    st = collections.Counter(
        ctx.verdicts[r.uid].status for r in ctx.rules
    )
    withsheet = sum(
        1 for r in ctx.rules if ctx.verdicts[r.uid].rfc_used
    )
    merged = sum(
        1
        for r in ctx.rules
        if ctx.verdicts[r.uid].merged_note
        and ctx.verdicts[r.uid].status == "NO"
    )
    kp = [
        (
            "Rules audited",
            len(ctx.rules),
            "All rows kept in the consolidated tabs.",
        ),
        (
            "Rules with an RFC port sheet",
            withsheet,
            "These could be compared.",
        ),
        (
            "PIR ISSUE = YES",
            st["YES"],
            "Source, destination or port not approved by the RFC.",
        ),
        ("PIR ISSUE = NO", st["NO"], "Matches the RFC port sheet."),
        (
            "REVIEW",
            st["REVIEW"],
            "Cannot be verified yet (sheet or name missing).",
        ),
        ("N/A", st["N/A"], "Removed rules."),
        (
            " NO with a merged-rule note",
            merged,
            (
                "Counted in NO: the rule merges lines and is broader"
                " than any single line."
            ),
        ),
    ]
    top = 6
    header_row(
        ws,
        top,
        ["Rule results", "Count", "Bar and meaning", "", "", ""],
    )
    ws.merge(top, 3, top, 6)
    big = max(len(ctx.rules), 1)
    for i, (a, b, cmt) in enumerate(kp, top + 1):
        ws.put(i, 1, a)
        ws.put(i, 2, b, CENTER)
        ws.put(i, 3, ("%s %s" % (_bar(b, big), cmt)).strip())
        for cc in (4, 5, 6):
            ws.put(i, cc, None)
        ws.merge(i, 3, i, 6)
    ic = collections.Counter(x.impl for x in ctx.rfc_results)
    pc = collections.Counter(x.pir for x in ctx.rfc_results)
    nosheet = len(_unsheeted(ctx))
    ic["Unable to Verify (no sheet)"] = nosheet
    pc["PIR Evidence Missing"] += nosheet
    impl_list = [
        "Correctly Implemented",
        "Partially Implemented",
        "Incorrectly Implemented",
        "Not Implemented",
        "Unable to Verify",
        "Unable to Verify (no sheet)",
    ]
    pir_list = [
        "PIR Verified",
        "PIR Pending",
        "PIR Deviation Found",
        "PIR Failed",
        "PIR Evidence Missing",
    ]
    r = top + len(kp) + 2
    for title, names, cnt in (
        ("RFC implementation status", impl_list, ic),
        ("PIR status", pir_list, pc),
    ):
        header_row(ws, r, [title, "RFCs", "Bar", "", "", ""])
        ws.merge(r, 3, r, 6)
        tmax = max(max(cnt[a] for a in names), 1)
        for i, a in enumerate(names, r + 1):
            ws.put(i, 1, a)
            ws.put(i, 2, cnt[a], CENTER)
            ws.put(i, 3, _bar(cnt[a], tmax))
            for cc in (4, 5, 6):
                ws.put(i, cc, None)
            ws.merge(i, 3, i, 6)
        r += len(names) + 2
    header_row(
        ws,
        r,
        [
            "By tab",
            "Rules",
            "PIR YES",
            "PIR NO",
            "REVIEW",
            "Risky rules",
        ],
    )
    by = collections.OrderedDict((td.name, []) for td in ctx.tabs)
    for ru in ctx.rules:
        by[ru.tab].append(ru)
    row = r + 1
    for name, rs in by.items():
        if rs:
            s = collections.Counter(
                ctx.verdicts[x.uid].status for x in rs
            )
            for ci, val in enumerate(
                [
                    name,
                    len(rs),
                    s["YES"],
                    s["NO"],
                    s["REVIEW"],
                    sum(
                        1 for x in rs if ctx.verdicts[x.uid].risky_rule
                    ),
                ],
                1,
            ):
                ws.put(row, ci, val, CENTER if ci > 1 else NORM)
            row += 1
    if ctx.job_history:
        row += 1
        ws.put(row, 1, "Recent Job Log (Audit Run History)", BOLD)
        row += 1
        header_row(
            ws,
            row,
            [
                "Run Timestamp",
                "Operator",
                "Report Date",
                "AlgoSec / RFCs",
                "Rules (YES / NO / REV)",
                "Overall Status",
            ],
        )
        row += 1
        for job in ctx.job_history[:10]:
            counts_txt = "%d (%d / %d / %d)" % (
                job.get("rules", 0),
                job.get("pir_yes", 0),
                job.get("pir_no", 0),
                job.get("review", 0),
            )
            files_txt = "%d / %d" % (
                job.get("algosec_files", 0),
                job.get("rfc_sheets", 0),
            )
            vals = [
                job.get("timestamp", ""),
                job.get("operator", ""),
                job.get("report_date", ""),
                files_txt,
                counts_txt,
                job.get("status", ""),
            ]
            for ci, val in enumerate(vals, 1):
                st_cell = (
                    status_sty(val)
                    if ci == 6
                    else (CENTER if ci in (3, 4, 5) else NORM)
                )
                ws.put(row, ci, val, st_cell)
            row += 1
    ws.set_widths([34, 16, 14, 16, 22, 20])


# === run everything ===
def discover_reports(paths, skipped=None):
    out = []
    for p in paths:
        if os.path.isdir(p):
            out += sorted(glob.glob(os.path.join(p, "*.xls*")))
        else:
            out.append(p)
    out = [p for p in out if not os.path.basename(p).startswith("~$")]
    if skipped is not None:
        skipped.extend(
            os.path.basename(p)
            for p in out
            if not p.lower().endswith((".xlsx", ".xlsm"))
        )
    return [p for p in out if p.lower().endswith((".xlsx", ".xlsm"))]


def _parse_report_date(value, reports):
    if value:
        if isinstance(value, datetime.date):
            return value
        for f in ("%d-%m-%Y", "%d/%m/%Y", "%Y-%m-%d", "%d-%b-%Y"):
            try:
                return datetime.datetime.strptime(value, f).date()
            except ValueError:
                continue
        raise AuditError(
            "Report date %r not understood. Use DD-MM-YYYY." % value
        )
    ends = [r.period[1] for r in reports if r.period]
    return max(ends) if ends else datetime.date.today()


def _free_name(path):
    base, ext = os.path.splitext(path)
    cand, n = path, 2
    while os.path.exists(cand):
        cand = "%s_%d%s" % (base, n, ext)
        n += 1
    return cand


def _check_rfc_dates(ctx):
    limit = ctx.cfg["checks"]["rfc_date_plausibility_days"]
    for s in ctx.sheets.values():
        if s.date is None:
            ctx.warn(
                "RFC%s: no Date found on the port sheet" % s.number,
                "INFO",
            )
            continue
        delta = (ctx.report_date - s.date).days
        if delta < 0:
            ctx.warn(
                "RFC%s: sheet date %s is after the report date;"
                " probably a typo" % (s.number, s.date),
                "WARN",
            )
        elif delta > limit:
            ctx.warn(
                "RFC%s: sheet date %s is %d days before the report"
                " date; probably a typo in the year"
                % (s.number, s.date, delta),
                "WARN",
            )



def build_smax_browser_script(rfc_numbers, base_url=None, tenant_id=None):
    base = (base_url or CONFIG["smax"]["base_url"] or "").rstrip("/")
    tid = str(tenant_id or CONFIG["smax"]["tenant_id"] or "").strip()
    if not base or not tid:
        raise AuditError(
            "SMAX base_url and tenant_id must be set in the config"
            " (smax.base_url / smax.tenant_id)."
        )
    rfcs_json = json.dumps([str(x).strip() for x in rfc_numbers if str(x).strip()])
    return (
        "(async () => {\n"
        "  const base = %s;\n"
        "  const tid = %s;\n"
        "  const rfcs = %s;\n"
        "  let ok = 0, miss = 0;\n"
        "  for (let i = 0; i < rfcs.length; i++) {\n"
        "    const id = rfcs[i];\n"
        "    try {\n"
        "      const res = await fetch(`${base}/rest/${tid}/ems/Change/${id}?layout=ChangeAttachments`, {credentials: 'include'});\n"
        "      const data = await res.json();\n"
        "      const ent = (data.entities || [])[0];\n"
        "      let raw = ent && ent.properties && ent.properties.ChangeAttachments;\n"
        "      if (typeof raw === 'string') { try { raw = JSON.parse(raw); } catch(e) { raw = null; } }\n"
        "      const items = (raw && (raw.complexTypeProperties || raw.attachments || raw)) || [];\n"
        "      const xls = (Array.isArray(items) ? items : []).filter(a => {\n"
        "        const p = (a && a.properties) || a || {};\n"
        "        const fn = String(p.file_name || '').toLowerCase();\n"
        "        const ext = String(p.file_extension || '').toLowerCase();\n"
        "        return ext === 'xlsx' || ext === 'xlsm' || fn.endsWith('.xlsx') || fn.endsWith('.xlsm');\n"
        "      });\n"
        "      if (!xls.length) { console.warn(`[${i+1}/${rfcs.length}] RFC${id}: no .xlsx attachment`); miss++; continue; }\n"
        "      for (let k = 0; k < xls.length; k++) {\n"
        "        const p = xls[k].properties || xls[k];\n"
        "        const aid = p.id;\n"
        "        const ext = (p.file_extension || 'xlsx').replace(/^\\./, '');\n"
        "        const outName = xls.length === 1 ? `RFC${id}.${ext}` : `RFC${id}_${k+1}.${ext}`;\n"
        "        const fRes = await fetch(`${base}/rest/${tid}/frs/file-list/${aid}`, {credentials: 'include'});\n"
        "        const blob = await fRes.blob();\n"
        "        const a = document.createElement('a');\n"
        "        a.href = URL.createObjectURL(blob);\n"
        "        a.download = outName;\n"
        "        document.body.appendChild(a);\n"
        "        a.click();\n"
        "        a.remove();\n"
        "        console.log(`[${i+1}/${rfcs.length}] Downloaded ${outName}`);\n"
        "        ok++;\n"
        "        await new Promise(r => setTimeout(r, 400));\n"
        "      }\n"
        "    } catch (err) { console.error(`RFC${id} failed:`, err); miss++; }\n"
        "  }\n"
        "  console.log(`Done: ${ok} file(s) downloaded, ${miss} RFC(s) skipped/failed.`);\n"
        "})();"
    ) % (json.dumps(base), json.dumps(tid), rfcs_json)


def smax_fetch_command(rfc_numbers, out_dir, cfg, user, script_path=None):
    sp = script_path or os.path.join(tool_dir(), "smax_fetch.py")
    s_cfg = (cfg or {}).get("smax", {})
    base = s_cfg.get("base_url") or CONFIG["smax"]["base_url"]
    tid = str(s_cfg.get("tenant_id") or CONFIG["smax"]["tenant_id"])
    rfcs = [str(x).strip() for x in rfc_numbers if str(x).strip()]
    return [
        sys.executable, sp,
        "--base-url", base,
        "--tenant", tid,
        "--user", user,
        "--out", out_dir,
        "--stdin-pw",
        "--rfc",
    ] + rfcs


def csv_safe(v):
    if isinstance(v, (datetime.date, datetime.datetime)):
        return v.strftime("%Y-%m-%d")
    s = "" if v is None else str(v)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


# === multi-day master consolidator (e.g. 90 days) ===
def merge_consolidated_folder(in_dir, out_dir, fmt="both", progress=None):
    if not os.path.isdir(in_dir):
        raise AuditError("Consolidated sheets folder not found: %s" % in_dir)
    files = [
        os.path.join(in_dir, f)
        for f in sorted(os.listdir(in_dir))
        if f.lower().startswith("daily_consolidated_")
        and f.lower().endswith((".xlsx", ".xlsm"))
        and not f.startswith("~$")
    ]
    if not files:
        raise AuditError("No Daily_Consolidated_*.xlsx files found in: %s" % in_dir)

    tab_headers = collections.OrderedDict()
    tab_rows = collections.OrderedDict()
    seen_keys = collections.defaultdict(set)
    dups_skipped = 0
    flat_headers = ["Firewall Tab"]
    flat_h_low = {"firewall tab"}
    flat_records = []
    files_read = 0

    for fp in files:
        bname = os.path.basename(fp)
        if progress:
            progress("Reading %s" % bname)
        bk = XlsxBook(fp)
        try:
            for sname in bk.visible_names():
                if sname.strip().lower() == "summary":
                    continue
                rows = bk.rows(sname)
                if not rows or len(rows) < 2:
                    continue
                raw_hdr = [clean(h).strip() for h in rows[0]]
                while raw_hdr and not raw_hdr[-1]:
                    raw_hdr.pop()
                if not raw_hdr:
                    continue
                hdr = []
                app_seen = 0
                for h in raw_hdr:
                    if h.lower() == "application":
                        app_seen += 1
                        hdr.append("RFC Application" if app_seen > 1 else h)
                    else:
                        hdr.append(h)
                if sname not in tab_headers:
                    tab_headers[sname] = list(hdr)
                    tab_rows[sname] = []
                th = tab_headers[sname]
                th_low = [h.lower() for h in th]
                for h in hdr:
                    if h and h.lower() not in flat_h_low:
                        flat_h_low.add(h.lower())
                        flat_headers.append(h)

                col_map = {}
                for j, h in enumerate(hdr):
                    hl = h.lower()
                    if hl in th_low:
                        col_map[j] = th_low.index(hl)

                key_cols = [
                    i for i, h in enumerate(th_low)
                    if h in ("change type", "name", "change time", "source", "destination", "service", "services & applications", "action")
                ]
                for r in rows[1:]:
                    if not any(clean(x).strip() for x in r):
                        continue
                    aligned = [None] * len(th)
                    for j, pos in col_map.items():
                        if j < len(r):
                            aligned[pos] = r[j]
                    if key_cols:
                        dkey = tuple(clean(aligned[i]).strip() for i in key_cols)
                    else:
                        dkey = tuple(clean(x).strip() for x in aligned)
                    if dkey in seen_keys[sname]:
                        dups_skipped += 1
                        continue
                    seen_keys[sname].add(dkey)
                    tab_rows[sname].append((aligned, bname))
                    rec_map = {"firewall tab": sname}
                    for j, h in enumerate(hdr):
                        if h and j < len(r):
                            rec_map[h.lower()] = r[j]
                    rec_map["consolidated from"] = bname
                    flat_records.append(rec_map)
            files_read += 1
        finally:
            bk.close()

    if not flat_records:
        raise AuditError("No rule rows found in the consolidated files in: %s" % in_dir)

    if "consolidated from" not in flat_h_low:
        flat_headers.append("CONSOLIDATED FROM")

    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.date.today().strftime("%d-%m-%Y")
    outs = []

    if fmt in ("both", "multitab"):
        m_path = _free_name(
            os.path.join(out_dir, "Master_Consolidated_%s.xlsx" % stamp)
        )
        bk = Book()
        sum_ws = bk.sheet("Summary")
        title_block(
            sum_ws,
            "DXC Technology — Master Consolidated Firewall Changes",
            [
                "DXC Technology • Built by Ganesh A | Merged %d file(s) | Total rules: %d | Generated: %s"
                % (files_read, len(flat_records), datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))
            ],
        )
        sum_hdr = [
            "Firewall Tab",
            "Total Rules",
            "Risky Rules",
            "PIR ISSUE = YES",
            "PIR ISSUE = NO",
            "REVIEW",
            "N/A",
        ]
        sum_rows = []
        tot = collections.Counter()
        for tname, th in tab_headers.items():
            ws = bk.sheet(tname)
            out_hdr = th + ["CONSOLIDATED FROM"]
            fills = dict(
                (i, AUTOHEAD)
                for i, h in enumerate(out_hdr, 1)
                if h in AUTO_COLS or h in EXTRA or h == "CONSOLIDATED FROM"
            )
            header_row(ws, 1, out_hdr, fills)
            pir_i = next((i for i, h in enumerate(th) if h.strip().lower() == "pir issue"), None)
            rsk_i = next((i for i, h in enumerate(th) if h.strip().lower() == "risky rules"), None)
            c_yes = c_no = c_rev = c_na = c_rsk = 0
            for ri, (vals, bname) in enumerate(tab_rows[tname], 2):
                full_row = vals + [bname]
                for ci, val in enumerate(full_row, 1):
                    hn = out_hdr[ci - 1]
                    st = NORM
                    if hn in ("PIR ISSUE", "RISKY RULES"):
                        st = status_sty(val) or NORM
                    elif hn == "MERGED-RULE NOTE" and val:
                        st = YELLOW
                    ws.put(ri, ci, val, st)
                if pir_i is not None:
                    pv = clean(vals[pir_i]).strip().upper()
                    if pv == "YES":
                        c_yes += 1
                    elif pv == "NO":
                        c_no += 1
                    elif pv == "REVIEW":
                        c_rev += 1
                    elif pv == "N/A":
                        c_na += 1
                if rsk_i is not None and clean(vals[rsk_i]).strip().upper() == "YES":
                    c_rsk += 1
            for i, h in enumerate(out_hdr, 1):
                ws.widths[i] = WIDTHS.get(h.strip().lower(), 18)
            ws.freeze, ws.zoom = (2, 3), 90
            if tab_rows[tname]:
                ws.filter = "A1:%s%d" % (_colname(len(out_hdr)), len(tab_rows[tname]) + 1)
            row_s = [tname, len(tab_rows[tname]), c_rsk, c_yes, c_no, c_rev, c_na]
            sum_rows.append(row_s)
            for idx_k, k in enumerate(sum_hdr[1:], 1):
                tot[k] += row_s[idx_k]
        sum_rows.append(["Total"] + [tot[k] for k in sum_hdr[1:]])
        last_s = table(
            sum_ws,
            4,
            sum_hdr,
            sum_rows,
            [28, 12, 12, 16, 16, 12, 10],
            center_cols=range(2, 8),
            freeze=False,
            filt=False,
        )
        for ci in range(1, len(sum_hdr) + 1):
            sum_ws.restyle(
                last_s, ci, sty(bold=True, fill="D9E1F2", h="center" if ci > 1 else None)
            )
        sum_ws.fit = True
        bk.save(m_path)
        outs.append(m_path)

    if fmt in ("both", "flat"):
        f_xlsx = _free_name(
            os.path.join(out_dir, "Master_Flat_All_Rules_%s.xlsx" % stamp)
        )
        f_csv = _free_name(
            os.path.join(out_dir, "Master_Flat_All_Rules_%s.csv" % stamp)
        )
        bk2 = Book()
        ws2 = bk2.sheet("All_Rules_Combined")
        fills2 = dict(
            (i, AUTOHEAD)
            for i, h in enumerate(flat_headers, 1)
            if h in AUTO_COLS or h in EXTRA or h in ("Firewall Tab", "CONSOLIDATED FROM")
        )
        header_row(ws2, 1, flat_headers, fills2)
        with open(f_csv, "w", encoding="utf-8-sig", newline="") as cf:
            cw = csv.writer(cf)
            cw.writerow(flat_headers)
            for ri, rec in enumerate(flat_records, 2):
                out_r = [rec.get(h.lower(), "") for h in flat_headers]
                cw.writerow([csv_safe(v) for v in out_r])
                for ci, val in enumerate(out_r, 1):
                    hn = flat_headers[ci - 1]
                    st = status_sty(val) if hn in ("PIR ISSUE", "RISKY RULES") else NORM
                    ws2.put(ri, ci, val, st or NORM)
        for i, h in enumerate(flat_headers, 1):
            ws2.widths[i] = WIDTHS.get(h.strip().lower(), 18)
        ws2.freeze, ws2.zoom = (2, 3), 90
        ws2.filter = "A1:%s%d" % (_colname(len(flat_headers)), len(flat_records) + 1)
        bk2.save(f_xlsx)
        outs.extend([f_xlsx, f_csv])

    return {
        "files_read": files_read,
        "total_rules": len(flat_records),
        "dups_skipped": dups_skipped,
        "tabs": len(tab_headers),
        "records": flat_records,
    }, outs


def run_audit(
    algosec_paths,
    rfc_folder,
    out_dir,
    cfg=None,
    report_date=None,
    progress=None,
    smax_path=None,
    operator=None,
    record_job=True,
    overrides_path=None,
):
    cfg = cfg or load_config()

    def step(msg):
        log.info(msg)
        if progress:
            progress(msg)

    ctx = AuditContext(cfg)
    if operator is not None and operator.strip():
        ctx.operator = operator.strip()
    elif not ctx.operator:
        ctx.operator = default_operator()
    skipped = []
    files = discover_reports(algosec_paths, skipped)
    for n in skipped:
        ctx.warn(
            "AlgoSec file %s skipped: only .xlsx/.xlsm is supported"
            " (open it in Excel and Save As .xlsx)." % n
        )
    if not files:
        raise AuditError(
            "No AlgoSec .xlsx files found in: %s"
            % ", ".join(algosec_paths)
        )
    step("Reading %d AlgoSec report(s)" % len(files))
    for p in files:
        try:
            ctx.reports.append(read_report(p))
        except AuditError as e:
            ctx.warn(str(e), "ERROR")
            log.error("%s", e)
    if not ctx.reports:
        raise AuditError(
            "None of the AlgoSec files could be read. First problem: %s"
            % ctx.warnings[0][1]
        )
    ctx.report_date = _parse_report_date(report_date, ctx.reports)
    step("Consolidating into tabs (HA rule)")
    ctx.tabs = build_tabs(ctx.reports, cfg)
    ctx.tab_headers = dict((t.name, t.headers) for t in ctx.tabs)
    ctx.rules = make_rules(ctx.tabs, cfg)
    if rfc_folder:
        step("Reading RFC port sheets")
        ctx.sheets, ctx.sheet_problems = load_rfc_folder(
            rfc_folder, cfg["rfc"]["filename_regex"], cfg["rfc"]
        )
        _check_rfc_dates(ctx)
    else:
        ctx.warn("No RFC folder given: every rule is REVIEW.", "WARN")
    step(
        "Checking %d rules against %d RFC sheet(s)"
        % (len(ctx.rules), len(ctx.sheets))
    )
    ctx.verdicts = dict(
        (r.uid, evaluate_rule(r, ctx.sheets, cfg)) for r in ctx.rules
    )
    ov_path = _resolve_overrides(cfg, overrides_path)
    ost = finalize_review(
        ctx, ov_path, (cfg.get("review") or {}).get("require_approval", True)
    )
    if ov_path:
        step(
            "Reviewer overrides: %d applied, %d pending approval, %d no"
            " longer match (rule changed)"
            % (len(ost["applied"]), len(ost["pending"]), len(ost["stale"]))
        )
        if ost["pending"]:
            ctx.warn(
                "%d reviewer override(s) are waiting for approval and were"
                " not applied." % len(ost["pending"]),
                "WARN",
            )
    ctx.rfc_results = evaluate_rfcs(ctx.sheets, ctx.rules, ctx.verdicts)
    ctx.duplicates = find_duplicates(ctx.rules)
    ctx.unexpected = find_unexpected(ctx.rules, ctx.verdicts)
    if smax_path:
        step(
            "Reading SMAX export for Title / RFC Owner / Asset Owner /"
            " Application / Expiry"
        )
        ctx.smax = load_smax(smax_path, cfg)
        for f, m in ctx.smax.problems:
            ctx.warn("SMAX file %s: %s" % (f, m), "WARN")
        seen = []
        for r in ctx.rules:
            for n in effective_rfcs(r, cfg):
                if n not in seen:
                    seen.append(n)
        lost = [n for n in seen if n not in ctx.smax.records]
        ctx.warn(
            "SMAX details found for %d of %d RFC(s)%s"
            % (
                len(seen) - len(lost),
                len(seen),
                (
                    (
                        "; not in the export: "
                        + ", ".join("RFC" + n for n in lost[:15])
                        + (" ..." if len(lost) > 15 else "")
                    )
                    if lost
                    else ""
                ),
            ),
            "WARN" if lost else "INFO",
        )
    ctx.owners = dict(
        (r.uid, asset_owner(r, ctx.sheets, cfg, ctx.smax))
        for r in ctx.rules
    )
    ctx.apps = dict(
        (r.uid, rule_application(r, ctx.sheets, cfg, ctx.smax))
        for r in ctx.rules
    )
    blank = sum(1 for r in ctx.rules if not ctx.owners[r.uid][0])
    if blank:
        ctx.warn(
            "Asset Owner is blank for %d of %d rule(s): no RFC sheet"
            " for them, or no owner written in it (see ASSET OWNER"
            " FROM)." % (blank, len(ctx.rules)),
            "WARN",
        )
    expected_tabs = [t["name"] for t in cfg["tabs"]]
    received_tabs = [t.name for t in ctx.tabs if t.name in expected_tabs and t.reports]
    missing_tabs = [n for n in expected_tabs if n not in received_tabs]
    ctx.coverage_summary = (len(received_tabs), len(expected_tabs), missing_tabs)
    if missing_tabs:
        ctx.warn(
            "Firewall coverage: %d of %d expected tab(s) received reports; missing: %s"
            % (len(received_tabs), len(expected_tabs), ", ".join(missing_tabs)),
            "WARN",
        )
    ctx.report_windows = sorted(set(
        ("%s to %s" % (rep.period[0].strftime("%Y-%m-%d"), rep.period[1].strftime("%Y-%m-%d")))
        if isinstance(rep.period, tuple) and len(rep.period) == 2
        else str(rep.period)
        for rep in ctx.reports if getattr(rep, "period", None)
    ))
    if len(ctx.report_windows) > 1:
        ctx.warn(
            "Multiple AlgoSec report windows detected: %s" % ", ".join(ctx.report_windows),
            "WARN",
        )
    ctx.input_custody = [_file_custody(rep.path, "AlgoSec") for rep in ctx.reports if getattr(rep, "path", "")]
    if rfc_folder:
        for s in sorted(ctx.sheets.values(), key=lambda x: x.number):
            for sp in (getattr(s, "all_paths", None) or [getattr(s, "path", "") or os.path.join(rfc_folder, s.filename)]):
                ctx.input_custody.append(_file_custody(sp, "RFC"))
    if smax_path:
        ctx.input_custody.append(_file_custody(smax_path, "SMAX"))
    if ov_path:
        ctx.input_custody.append(_file_custody(ov_path, "Overrides"))
    ctx.status = overall_status(ctx)
    os.makedirs(out_dir, exist_ok=True)
    stamp = ctx.report_date.strftime("%d-%m-%Y")
    daily_path = _free_name(
        os.path.join(out_dir, "Daily_Consolidated_%s.xlsx" % stamp)
    )
    audit_path = _free_name(
        os.path.join(out_dir, "RFC_Audit_Report_%s.xlsx" % stamp)
    )
    st_counts = collections.Counter(
        ctx.verdicts[r.uid].status for r in ctx.rules
    )
    job_entry = {
        "timestamp": ctx.run_time,
        "operator": ctx.operator or "(not set)",
        "report_date": stamp,
        "algosec_files": len(ctx.reports),
        "rfc_sheets": len(ctx.sheets),
        "rules": len(ctx.rules),
        "pir_yes": st_counts["YES"],
        "pir_no": st_counts["NO"],
        "review": st_counts["REVIEW"],
        "risky": sum(
            1 for r in ctx.rules if ctx.verdicts[r.uid].risky_rule
        ),
        "status": ctx.status,
        "outputs": [daily_path, audit_path],
        "overrides_applied": len(ctx.override_stats.get("applied", [])),
        "tool_pir_yes": sum(
            1 for r in ctx.rules if ctx.verdicts[r.uid].tool_status == "YES"
        ),
    }
    step("Writing the daily consolidated workbook")
    outs = [write_daily(ctx, daily_path)]
    step("Writing the RFC audit workbook")
    outs.append(write_audit(ctx, audit_path))
    ctx.output_custody = [_file_custody(p, "Output") for p in outs]
    job_entry["tool_version"] = VERSION
    job_entry["config_hash"] = ctx.config_hash
    job_entry["firewall_coverage"] = "%d/%d" % (ctx.coverage_summary[0], ctx.coverage_summary[1])
    job_entry["input_hashes"] = [{"name": c["name"], "sha256": c["sha256"]} for c in ctx.input_custody]
    job_entry["output_hashes"] = [{"name": c["name"], "sha256": c["sha256"]} for c in ctx.output_custody]
    if record_job:
        ctx.job_history = append_job_log(job_entry)
    else:
        ctx.job_history = [job_entry]
    step("Done. Overall status: %s" % ctx.status)
    return ctx, outs


# === self-test ===
def _sample(folder):
    H = CONFIG["layout_headers"]["PA"]

    def row(name, s, d, svc, change="Added"):
        v = dict.fromkeys(H, "")
        v.update(
            {
                "Change Type": change + "\n ",
                "Name": name + "\n ",
                "Change Time": "Nov 08, 2026 09:10:00\n ",
                "Source": "H_%s:\n%s\n " % (s, s),
                "Destination": "H_%s:\n%s\n " % (d, d),
                "Service": svc + "\n ",
                "Action": "allow\n ",
                "Enable": "enabled\n ",
            }
        )
        return [v[h] for h in H]

    def algosec(name, rows):
        bk = Book()
        g = bk.sheet("GENERAL")
        g.raw(3, 1, "Total Number of Changes")
        g.raw(3, 2, str(len(rows) + 1))
        ws = bk.sheet("RULES")
        for c, h in enumerate(H, 1):
            ws.raw(2, c, h)
        for r, vals in enumerate(rows, 3):
            for c, x in enumerate(vals, 1):
                ws.raw(r, c, x)
        bk.sheet("POLICY OBJECTS").raw(3, 1, "Added\n ")
        bk.sheet("POLICY OBJECTS").raw(2, 1, "Change Type")
        bk.save(os.path.join(folder, name))

    def rfc(num, s, d, port, so="Mr. Asha Rao", do="Mr Vikram Shah"):
        bk = Book()
        ws = bk.sheet("Sheet1")
        ws.raw(2, 2, "Date")
        ws.raw(2, 6, datetime.date(2026, 11, 2))
        for c, t in (
            (1, "Sr. No."),
            (2, "Source"),
            (7, "Destination"),
            (13, "Port Type (UDP/TCP)"),
            (14, "Direction"),
        ):
            ws.raw(8, c, t)
        for c in (3, 8):
            ws.raw(9, c, "Server IP Address")
        ws.raw(9, 6, "Source Owner (CM or Above)")
        ws.raw(9, 10, "Destination Port")
        ws.raw(9, 12, "Dest. Server Owner (CM or Above)")
        for c, v in (
            (1, 1),
            (3, s),
            (6, so),
            (8, d),
            (10, port),
            (12, do),
            (13, "TCP"),
        ):
            ws.raw(10, c, v)
        bk.save(os.path.join(folder, "RFC_%s.xlsx" % num))

    tail = (
        "_vsys1_-_Changes_Summary_Report_Nov_08_2026_-_Nov_08_2026.xlsx"
    )
    one = row("RFC900000001", "10.1.1.5", "10.2.1.10", "TCP_443")
    algosec(
        "172_16_188_15" + tail,
        [
            one,
            row("RFC900000002-1", "10.1.2.5", "10.2.2.10", "TCP_1521"),
            row("RFC900000003", "10.1.3.5", "10.2.3.10", "TCP_22"),
            row("RFC900000004", "10.1.4.5", "10.2.4.10", "443-tcp"),
            row("Test-no-rfc", "10.1.6.5", "10.2.6.10", "TCP_8080"),
            row(
                "+ RFC900000005\n- RFC900000001\n ",
                "10.1.5.5",
                "10.2.5.10",
                "+ TCP_8443\n- TCP_8080\n ",
                "Edited",
            ),
            row(
                "RFC900000006",
                "172.16.53.165\n172.16.53.166",
                "172.17.52.196\n172.16.52.201",
                "TCP_13555",
            ),
            row(
                "RFC900000007",
                "172.16.60.10\n172.17.60.20",
                "172.16.70.100",
                "TCP_8443",
            ),
        ],
    )
    algosec(
        "172_16_188_16" + tail,
        [
            one,
            row("RFC900000002-1", "10.1.2.5", "10.2.2.11", "TCP_1521"),
        ],
    )
    for n, s, d, p in (
        ("900000001", "10.1.1.5", "10.2.1.10", "443"),
        ("900000002", "10.1.2.5", "10.2.2.10", "1522"),
        ("900000003", "10.1.3.5", "10.2.3.10", "22"),
        ("900000005", "10.1.5.5", "10.2.5.10", "8443"),
    ):
        same = "MR ASHA RAO" if n == "900000003" else "Mr Vikram Shah"
        rfc(n, s, d, p, do=same)
    # Two-row RFC (same source & port, different destinations) combined into 1 rule
    bk6 = Book()
    ws6 = bk6.sheet("Sheet1")
    ws6.raw(2, 2, "Date")
    ws6.raw(2, 6, datetime.date(2026, 11, 2))
    for c, t in ((1, "Sr. No."), (2, "Source"), (7, "Destination"), (13, "Port Type (UDP/TCP)")):
        ws6.raw(8, c, t)
    for c in (3, 8):
        ws6.raw(9, c, "Server IP Address")
    ws6.raw(9, 10, "Destination Port")
    ws6.raw(10, 1, 1); ws6.raw(10, 3, "172.16.53.165\n172.16.53.166"); ws6.raw(10, 8, "172.17.52.196"); ws6.raw(10, 10, "13555"); ws6.raw(10, 13, "TCP")
    ws6.raw(11, 1, 2); ws6.raw(11, 3, "172.16.53.165\n172.16.53.166"); ws6.raw(11, 8, "172.16.52.201"); ws6.raw(11, 10, "13555"); ws6.raw(11, 13, "TCP")
    bk6.save(os.path.join(folder, "RFC_900000006.xlsx"))
    # Two-row RFC (same destination & port, different sources) combined into 1 rule
    bk7 = Book()
    ws7 = bk7.sheet("Sheet1")
    ws7.raw(2, 2, "Date")
    ws7.raw(2, 6, datetime.date(2026, 11, 2))
    for c, t in ((1, "Sr. No."), (2, "Source"), (7, "Destination"), (13, "Port Type (UDP/TCP)")):
        ws7.raw(8, c, t)
    for c in (3, 8):
        ws7.raw(9, c, "Server IP Address")
    ws7.raw(9, 10, "Destination Port")
    ws7.raw(10, 1, 1); ws7.raw(10, 3, "172.16.60.10"); ws7.raw(10, 8, "172.16.70.100"); ws7.raw(10, 10, "8443"); ws7.raw(10, 13, "TCP")
    ws7.raw(11, 1, 2); ws7.raw(11, 3, "172.17.60.20"); ws7.raw(11, 8, "172.16.70.100"); ws7.raw(11, 10, "8443"); ws7.raw(11, 13, "TCP")
    bk7.save(os.path.join(folder, "RFC_900000007.xlsx"))


NETWORK_MODULES = (
    "socket",
    "urllib",
    "http",
    "ftplib",
    "smtplib",
    "telnetlib",
    "requests",
    "ssl",
    "xmlrpc",
    "asyncio",
)


def run_selftest():
    import shutil

    lines, fails = [], []

    def check(label, cond):
        lines.append("%s %s" % ("PASS" if cond else "FAIL", label))
        if not cond:
            fails.append(label)

    tmp = tempfile.mkdtemp(prefix="fwaudit_selftest_")
    try:
        _sample(tmp)
        ctx, outs = run_audit(
            [tmp],
            tmp,
            os.path.join(tmp, "out"),
            load_config(),
            report_date="08-11-2026",
            operator="selftest_user",
            record_job=False,
            overrides_path="",
        )
        by = dict((r.name, ctx.verdicts[r.uid]) for r in ctx.rules)
        check("two workbooks written", len(outs) == 2)
        check(
            "9 rules after HA rule (mirror dropped)",
            len(ctx.rules) == 9,
        )
        check("exact match is NO", by["RFC900000001"].status == "NO")
        check("wrong port is YES", by["RFC900000002-1"].status == "YES")
        check("risky port 22", by["RFC900000003"].risky_ports == ["22"])
        check(
            "no RFC sheet is REVIEW",
            by["RFC900000004"].status == "REVIEW",
        )
        check(
            "no RFC number is REVIEW",
            by["Test-no-rfc"].status == "REVIEW",
        )
        check(
            "Edited rule +/- markers", by["RFC900000005"].status == "NO"
        )
        check(
            "multi-row same-src/port combined dest is NO", by["RFC900000006"].status == "NO"
        )
        check(
            "multi-row same-dst/port combined src is NO", by["RFC900000007"].status == "NO"
        )
        res = dict((x.number, x) for x in ctx.rfc_results)
        check(
            "RFC with a bad rule",
            res["900000002"].pir == "PIR Deviation Found",
        )
        check(
            "GENERAL checksum OK",
            all(r.checksum_ok for r in ctx.reports),
        )
        check("overall status", ctx.status == "ATTENTION REQUIRED")
        own = dict((r.name, ctx.owners[r.uid][0]) for r in ctx.rules)
        both = "Source: Mr. Asha Rao | Destination: Mr Vikram Shah"
        check(
            "Asset Owner: source and destination from the RFC",
            own["RFC900000001"] == both,
        )
        check(
            "Asset Owner: same person on both sides shown once",
            own["RFC900000003"] == "Mr. Asha Rao",
        )
        check(
            "Asset Owner: blank when there is no RFC sheet",
            own["RFC900000004"] == "",
        )
        wb = XlsxBook(outs[0])
        trows = wb.rows("DC_Core")
        wb.close()
        ai, ni = trows[0].index("Asset Owner"), trows[0].index("Name")
        got = [
            clean(x[ai] if ai < len(x) else None)
            for x in trows[1:]
            if clean(x[ni]).strip() == "RFC900000001"
        ]
        check(
            "Asset Owner written into the daily workbook",
            got == [both],
        )
        pi = trows[0].index("PREPARED BY")
        check(
            "Operator written into PREPARED BY",
            clean(trows[1][pi]).strip() == "selftest_user",
        )
        for o in outs:
            with zipfile.ZipFile(o) as z:
                for n in z.namelist():
                    ET.fromstring(z.read(n))
        bk = XlsxBook(outs[1])
        check("audit workbook has the 8 sheets", len(bk.names()) >= 8)
        bk.close()
        # --- Regression tests for Bugs #1-#10 ---
        v_port = Verdict()
        v_port.lines_used = [("900000001", 1)]
        ap_ports = _approved(ctx, v_port, "port")
        check("Bug#1 _approved port returns PortSet", isinstance(ap_ports, PortSet) and ap_ports.contains(443))
        shutil.copy2(outs[0], os.path.join(tmp, "out", "Daily_Consolidated_08-11-2026_2.xlsx"))
        mres, _mouts = merge_consolidated_folder(os.path.join(tmp, "out"), os.path.join(tmp, "out", "master"), fmt="both")
        check("Bug#2 consolidator skips RFC_Audit_Report & dedups", mres["files_read"] == 2 and mres["total_rules"] == 9 and mres["dups_skipped"] == 9)
        check("Bug#3 PA daily header has no duplicate Application", trows[0].count("Application") == 1 and "RFC Application" in trows[0])
        exp_ctx = AuditContext(ctx.cfg)
        exp_ctx.report_date = datetime.date(2026, 11, 8)
        r_exp = Rule()
        r_exp.uid, r_exp.tab, r_exp.name, r_exp.chain = 0, "DC_Core", "RFC900000001", ["900000001"]
        r_exp.src, r_exp.dst = parse_ip_text("10.1.1.1"), parse_ip_text("10.2.2.2")
        r_exp.ports, r_exp.svc_tokens = PortSet([("tcp", 443, 443)]), ["443"]
        exp_ctx.rules = [r_exp]
        exp_ctx.owners = {0: ("Asset Owner X", "RFC900000001")}
        exp_ctx.smax = SmaxData()
        exp_ctx.smax.records["900000001"] = {"rfc_owner": "alice@dxc.com", "expiry": "2026-11-01 10:30:00", "title": "Temp"}
        exp_p = os.path.join(tmp, "out", "Expiry_Test.xlsx")
        export_expiry_cleanup_xlsx(exp_ctx, exp_p)
        ewb = XlsxBook(exp_p)
        erows = ewb.rows("Owner Summary")
        ewb.close()
        check("Bug#4 expiry cleanup groups by rfc_owner", any(clean(r[0]) == "alice@dxc.com" for r in erows))
        r_multi = Rule()
        r_multi.tab, r_multi.name, r_multi.chain = "DC_Core", "RFC900000001_RFC999999999", ["900000001", "999999999"]
        r_multi.src, r_multi.dst = parse_ip_text("10.1.1.1"), parse_ip_text("10.2.2.2")
        r_multi.ports, r_multi.svc_tokens = PortSet([("tcp", 443, 443)]), ["443"]
        r_multi.change_type, r_multi.action, r_multi.any_service = "Added", "Allow", False
        r_multi.desc_rfcs = []
        v_multi = evaluate_rule(r_multi, ctx.sheets, ctx.cfg)
        check("Bug#5 multi_rfc=last requires last RFC sheet", v_multi.status == "REVIEW" and v_multi.needed == "999999999")
        ha_dir = os.path.join(tmp, "ha_test")
        os.makedirs(ha_dir, exist_ok=True)
        h_pa = CONFIG["layout_headers"]["PA"]
        def _mk_ha_rep(fname, rname):
            bk_ha = Book()
            ws_ha = bk_ha.sheet("RULES")
            ws_ha.put(1, 1, "Changes Summary Report")
            for ci, hn in enumerate(h_pa, 1):
                ws_ha.put(3, ci, hn)
            vals = dict.fromkeys(h_pa, "")
            vals.update({"Change Type": "Added", "Name": rname, "Source": "10.1.1.1", "Destination": "10.2.2.2", "Service": "443", "Action": "Allow", "Enable": "Enabled"})
            for ci, hn in enumerate(h_pa, 1):
                ws_ha.put(4, ci, vals[hn])
            fp_ha = os.path.join(ha_dir, fname)
            bk_ha.save(fp_ha)
            return read_report(fp_ha)
        rep_p = _mk_ha_rep("172.16.188.15 - Changes Summary Report Oct 17 2026 - Oct 17 2026.xlsx", "RFC900000001")
        rep_s = _mk_ha_rep("172.16.188.16 - Changes Summary Report Oct 17 2026 - Oct 17 2026.xlsx", "RFC900000001")
        ha_tabs = build_tabs([rep_s, rep_p], ctx.cfg)
        dc_tab = next(t for t in ha_tabs if t.name == "DC_Core")
        check("Bug#6 HA dotted primary dedups partner", len(dc_tab.rows) == 1 and dc_tab.rows[0].origin == "primary" and dc_tab.ha_stats["mirrors_dropped"] == 1)
        pa_res = parse_addr_cell("H_10.1.1.1:\n10.1.1.1\nGRP_Servers")
        check("Bug#7 parse_addr_cell captures lone unresolved object", "GRP_Servers" in pa_res.unresolved)
        check("Bug#8 expiry_status parses timestamp string", expiry_status("2026-11-01 10:30:00", datetime.date(2026, 11, 8)) == "EXPIRED" and expiry_status("Nov 01, 2026 10:30 AM", datetime.date(2026, 11, 8)) == "EXPIRED")
        r_deny = Rule()
        r_deny.tab, r_deny.name, r_deny.change_type, r_deny.action = "DC_Core", "Cleanup", "Added", "Drop"
        r_deny.src, r_deny.dst, r_deny.ports, r_deny.any_service = IPSet.any(), IPSet.any(), PortSet([("tcp", 23, 23)]), False
        check("Bug#9 risky skips deny rules", risky(r_deny, ctx.cfg) == [])
        check("Bug#10 csv_safe escapes formula prefixes", csv_safe("+ RFC900000005") == "'+ RFC900000005" and csv_safe("- TCP_8080") == "'- TCP_8080")
        v_en, _ = run_pir_test_case("RFC900000006", "Added", "Allow", "10.1.1.1", "10.2.2.2, 10.2.2.3", "443", [("900000006", 1, "10.1.1.1", "10.2.2.2", "tcp/443"), ("900000006", 2, "10.1.1.1", "10.2.2.3", "tcp/443")], ctx.cfg)
        strict_cfg = json.loads(json.dumps(ctx.cfg))
        strict_cfg["policy"]["combined_row_grouping"] = "strict"
        v_st, _ = run_pir_test_case("RFC900000006", "Added", "Allow", "10.1.1.1", "10.2.2.2, 10.2.2.3", "443", [("900000006", 1, "10.1.1.1", "10.2.2.2", "tcp/443"), ("900000006", 2, "10.1.1.1", "10.2.2.3", "tcp/443")], strict_cfg)
        check("PIR control combined_row_grouping enabled vs strict", v_en.status == "NO" and v_st.status == "YES")
        rem_cfg = json.loads(json.dumps(ctx.cfg))
        rem_cfg["policy"]["removed_rules"] = "check"
        v_rem, _ = run_pir_test_case("RFC900000001", "Removed", "Allow", "10.1.1.1", "10.2.2.2", "443", [("900000001", 1, "10.1.1.1", "10.2.2.2", "tcp/443")], rem_cfg)
        check("PIR control removed_rules=check evaluates rule", v_rem.status == "NO")
        check("Evidence config_hash & coverage_summary populated", len(ctx.config_hash) == 16 and ctx.coverage_summary[1] == len(ctx.cfg["tabs"]) and ctx.coverage_summary[0] >= 1)
        check("Evidence input & output SHA-256 custody recorded", bool(ctx.input_custody) and all(len(c["sha256"]) == 64 for c in ctx.input_custody) and len(ctx.output_custody) == 2 and all(len(c["sha256"]) == 64 for c in ctx.output_custody))
        chk_wb = XlsxBook(outs[1])
        chk_rows = chk_wb.rows("Checks")
        chk_wb.close()
        check("Evidence Checks sheet includes Chain of Custody", any(any("Chain of Custody" in clean(cell) for cell in row) for row in chk_rows))
        ev_json = os.path.join(tmp, "out", "Evidence_Test.json")
        export_compliance_json(ctx, ev_json, "all")
        with open(ev_json, "r", encoding="utf-8") as ef:
            ev_data = json.load(ef)
        check("Evidence JSON includes chain_of_custody & config_hash", ev_data.get("config_hash") == ctx.config_hash and len(ev_data.get("chain_of_custody", {}).get("outputs", [])) == 2)
        check("CIDR with space before slash parses full subnet", parse_ip_text("10.255.24.0 /22").count() == 1024)
        p_lbl, unk_lbl, _ = parse_rfc_ports("SNMP (161), Reverse DNS (53)", "udp")
        check("RFC ports parse parenthesized labels", p_lbl.contains(161) and p_lbl.contains(53) and not unk_lbl)
        smax_js = build_smax_browser_script(["220013247"])
        check("SMAX browser downloader script builds cleanly", "220013247" in smax_js and "ChangeAttachments" in smax_js and "frs/file-list" in smax_js)
        scmd = smax_fetch_command(["220013247"], tmp, ctx.cfg, "ga43")
        check("SMAX fetch command builds cleanly", "--stdin-pw" in scmd and "220013247" in scmd and "246334335" in scmd)
        mp_dir = os.path.join(tmp, "rfc_multipart")
        os.makedirs(mp_dir, exist_ok=True)
        for part_i, port_v in ((1, "80"), (2, "443"), (3, "8080")):
            bk_mp = Book()
            ws_mp = bk_mp.sheet("Port Sheet")
            ws_mp.put(1, 1, "Sr. No."); ws_mp.put(1, 2, "Source"); ws_mp.put(1, 7, "Destination")
            ws_mp.put(2, 1, "Sr. No."); ws_mp.put(2, 2, "Server IP Address"); ws_mp.put(2, 7, "Server IP Address"); ws_mp.put(2, 10, "Destination Port"); ws_mp.put(2, 13, "Pot Type")
            ws_mp.put(3, 1, part_i); ws_mp.put(3, 2, "10.1.1.1"); ws_mp.put(3, 7, "10.2.2.2"); ws_mp.put(3, 10, port_v); ws_mp.put(3, 13, "tcp")
            bk_mp.save(os.path.join(mp_dir, "RFC245677789_%d.xlsx" % part_i))
        mp_sheets, mp_probs = load_rfc_folder(mp_dir)
        mp_sh = mp_sheets.get("245677789")
        check("Multi-part RFC_1/_2/_3 merge as single RFC", mp_sh is not None and len(mp_sh.lines) == 3 and len(getattr(mp_sh, "all_paths", [])) == 3 and not mp_probs)
        extless_dir = os.path.join(tmp, "rfc_extless")
        os.makedirs(extless_dir, exist_ok=True)
        bk_el = Book()
        ws_el = bk_el.sheet("Port Sheet")
        ws_el.put(1, 1, "Sr. No."); ws_el.put(1, 2, "Source"); ws_el.put(1, 7, "Destination")
        ws_el.put(2, 1, "Sr. No."); ws_el.put(2, 2, "Server IP Address"); ws_el.put(2, 7, "Server IP Address"); ws_el.put(2, 10, "Destination Port"); ws_el.put(2, 13, "Pot Type")
        ws_el.put(3, 1, 1); ws_el.put(3, 2, "10.1.1.1"); ws_el.put(3, 7, "10.2.2.2"); ws_el.put(3, 10, "443"); ws_el.put(3, 13, "tcp")
        bk_el.save(os.path.join(extless_dir, "RFC255664422"))
        el_sheets, el_probs = load_rfc_folder(extless_dir)
        check("Extensionless RFC255664422 loads like .xlsx", "255664422" in el_sheets and len(el_sheets["255664422"].lines) == 1 and not el_probs)
        # --- v2.6 reviewer overrides / confidence / explain ---
        rb = dict((r.name, r) for r in ctx.rules)
        ov_file = os.path.join(tmp, "overrides.json")
        ovs = [
            new_override(rb["RFC900000002-1"], "NO", OVERRIDE_REASONS[0],
                         "Port 1521 approved in RFC900000099", "analyst1", "approved"),
            new_override(rb["Test-no-rfc"], "NO", OVERRIDE_REASONS[-2], "", "analyst1"),
            new_override(rb["RFC900000004"], "NO", OVERRIDE_REASONS[3], "",
                         "analyst1", "approved", expires="01-01-2026"),
        ]
        stale = new_override(rb["RFC900000003"], "NO", OVERRIDE_REASONS[0], "", "analyst1", "approved")
        stale["fingerprint"] = "0" * 24
        ovs.append(stale)
        save_overrides({"version": 1, "overrides": ovs}, ov_file)
        ctx2, outs2 = run_audit([tmp], tmp, os.path.join(tmp, "out_ov"), load_config(),
                                report_date="08-11-2026", operator="selftest_user",
                                record_job=False, overrides_path=ov_file)
        by2 = dict((r.name, ctx2.verdicts[r.uid]) for r in ctx2.rules)
        check("override approved: tool YES kept, final NO",
              by2["RFC900000002-1"].tool_status == "YES" and by2["RFC900000002-1"].status == "NO")
        check("override proposed only: not applied (maker-checker)",
              by2["Test-no-rfc"].status == "REVIEW" and len(ctx2.override_stats["pending"]) == 1)
        check("override expired: not applied", by2["RFC900000004"].status == "REVIEW"
              and len(ctx2.override_stats["expired"]) == 1)
        check("override on changed rule: not applied (stale)",
              by2["RFC900000003"].status == by2["RFC900000003"].tool_status
              and by2["RFC900000003"].override is None
              and any(r.name == "RFC900000003" for r, _ in ctx2.override_stats["stale"]))
        check("fingerprint stable across runs",
              rule_fingerprint(rb["RFC900000001"]) == ctx2.verdicts[[r for r in ctx2.rules if r.name == "RFC900000001"][0].uid].fingerprint)
        check("confidence set on every rule", all(ctx2.verdicts[r.uid].confidence for r in ctx2.rules))
        check("confidence High for exact match, Low for no RFC",
              by2["RFC900000001"].confidence == "High" and by2["Test-no-rfc"].confidence == "Low")
        ex = explain_verdict(rb["RFC900000002-1"], ctx.verdicts[rb["RFC900000002-1"].uid])
        check("explain shows failing port step", any(s == "Ports inside RFC" and res == "FAIL" for s, res, _ in ex))
        js = json.dumps(results_to_dict(ctx2), default=str)
        check("results export is JSON", '"rules"' in js and '"evidence"' in js)
        ab2 = XlsxBook([o for o in outs2 if "RFC_Audit" in o][0])
        check("audit workbook has Reviewer Overrides sheet", "Reviewer Overrides" in ab2.names())
        ab2.close()
        check("overrides file in chain of custody", any(c.get("role") == "Overrides" for c in ctx2.input_custody))
        # --- v2.6 RFC reader robustness ---
        rr_dir = os.path.join(tmp, "rfc_robust")
        os.makedirs(rr_dir, exist_ok=True)
        # (a) merged group headers, synonyms, merged Sr over two data rows
        bk_m = Book()
        w = bk_m.sheet("Port Details")
        w.put(1, 1, "S.No"); w.merge(1, 1, 2, 1)
        w.put(1, 2, "Source Details"); w.merge(1, 2, 1, 5)
        w.put(1, 6, "Destination Details"); w.merge(1, 6, 1, 10)
        w.put(2, 2, "Server Name"); w.put(2, 3, "IP Address"); w.put(2, 4, "Owner")
        w.put(2, 6, "Server Name"); w.put(2, 7, "IP Address"); w.put(2, 8, "Port No."); w.put(2, 9, "Protocol"); w.put(2, 10, "Owner")
        w.put(3, 1, 1); w.merge(3, 1, 4, 1)
        w.put(3, 3, "10.10.1.1"); w.put(3, 7, "10.20.1.1"); w.put(3, 8, "443"); w.put(3, 9, "TCP"); w.put(3, 4, "Asha")
        w.put(4, 3, "10.10.1.2"); w.put(4, 7, "10.20.1.1"); w.put(4, 8, "443"); w.put(4, 9, "TCP")
        w.put(5, 1, 2); w.put(5, 3, "10.10.1.3"); w.put(5, 7, "10.20.1.9"); w.put(5, 8, "1521"); w.put(5, 9, "TCP")
        bk_m.save(os.path.join(rr_dir, "RFC300000001.xlsx"))
        # (b) three-row header (Source > Server > IP Address)
        bk_3 = Book()
        w = bk_3.sheet("RFC")
        w.put(1, 1, "Sr. No."); w.put(1, 2, "Source"); w.merge(1, 2, 1, 3); w.put(1, 4, "Destination"); w.merge(1, 4, 1, 6)
        w.put(2, 2, "Server"); w.put(2, 4, "Server")
        w.put(3, 2, "IP Address"); w.put(3, 4, "IP Address"); w.put(3, 5, "Destination Port"); w.put(3, 6, "Port Type")
        w.put(4, 1, 1); w.put(4, 2, "10.30.0.0/24"); w.put(4, 4, "10.40.0.5"); w.put(4, 5, "22"); w.put(4, 6, "tcp")
        bk_3.save(os.path.join(rr_dir, "RFC300000002.xlsx"))
        # (c) single-row header, no Sr column, plus Instructions sheet and 2nd port sheet
        bk_s = Book()
        ins = bk_s.sheet("Instructions")
        ins.put(1, 1, "Source IP"); ins.put(1, 2, "Destination IP"); ins.put(1, 3, "Port")
        ins.put(2, 1, "0.0.0.0/0"); ins.put(2, 2, "0.0.0.0/0"); ins.put(2, 3, "1-65535")
        w = bk_s.sheet("DC")
        w.put(1, 1, "Source IP"); w.put(1, 2, "Destination IP"); w.put(1, 3, "Destination Port"); w.put(1, 4, "Protocol")
        w.put(2, 1, "10.50.0.1"); w.put(2, 2, "10.60.0.1"); w.put(2, 3, "8443"); w.put(2, 4, "TCP")
        w2 = bk_s.sheet("DR")
        w2.put(1, 1, "Source IP"); w2.put(1, 2, "Destination IP"); w2.put(1, 3, "Destination Port"); w2.put(1, 4, "Protocol")
        w2.put(2, 1, "10.51.0.1"); w2.put(2, 2, "10.61.0.1"); w2.put(2, 3, "8443"); w2.put(2, 4, "TCP")
        bk_s.save(os.path.join(rr_dir, "RFC300000003.xlsx"))
        # (d) unreadable layout mapped by a template; IPv6 in the RFC
        bk_t = Book()
        w = bk_t.sheet("Form")
        w.put(5, 1, "#"); w.put(5, 2, "From"); w.put(5, 3, "To"); w.put(5, 4, "Svc")
        w.put(6, 1, 1); w.put(6, 2, "10.70.0.1, 2001:db8::1"); w.put(6, 3, "10.80.0.1"); w.put(6, 4, "53/udp")
        bk_t.save(os.path.join(rr_dir, "RFC300000004.xlsx"))
        rcfg = {"templates": [{"name": "Form", "file_regex": "300000004", "sheet": "^Form$",
                               "header_row": 5, "columns": {"sr": "A", "src_ip": "B", "dst_ip": "C", "port": "D"}}]}
        no_tpl, no_tpl_probs = load_rfc_folder(rr_dir)
        rr, rr_probs = load_rfc_folder(rr_dir, rfc_cfg=rcfg)
        a = rr.get("300000001")
        check("RFC merged headers + synonyms read",
              a is not None and len(a.lines) == 3 and a.lines[1].sr == 1
              and a.lines[0].src.overlaps(IPSet([(ip2i("10.10.1.1"), ip2i("10.10.1.1"))]))
              and a.lines[2].sr == 2 and a.lines[2].ports.contains(1521, "tcp"))
        check("RFC merged owner column read", a is not None and "Asha" in " ".join(a.lines[0].src_owners))
        b = rr.get("300000002")
        check("RFC three-row header read", b is not None and len(b.lines) == 1 and b.lines[0].ports.contains(22, "tcp"))
        c = rr.get("300000003")
        check("RFC single-row header, auto Sr, two sheets, sample sheet skipped",
              c is not None and len(c.lines) == 2 and sorted(c.sheets) == ["DC", "DR"]
              and not any(l.src.is_any() for l in c.lines))
        d = rr.get("300000004")
        check("RFC template maps unreadable layout", d is not None and len(d.lines) == 1 and d.lines[0].ports.contains(53, "udp"))
        check("RFC without template reports the problem", "300000004" not in no_tpl and any("RFC300000004" in n for n, _ in no_tpl_probs))
        check("RFC IPv6 flagged, not dropped", d is not None and any("IPv6" in x for x in d.warnings))
        check("IPv6 tokens found", ipv6_tokens("10.1.1.1 2001:db8::/32 aa:bb:cc:dd:ee:ff") == ["2001:db8::/32"])
        check("expiry warning days configurable", expiry_status("2026-11-30", datetime.date(2026, 11, 1), warn_days=60).startswith("EXPIRING") and expiry_status("2026-11-30", datetime.date(2026, 11, 1), warn_days=10) == "ACTIVE")
        if getattr(sys, "frozen", False):
            check("no network modules imported", True)
        else:
            with open(
                os.path.abspath(__file__), "r", encoding="utf-8", errors="replace"
            ) as f:
                src = f.read()
            pat = r"^\s*(?:import|from)\s+(%s)\b" % "|".join(
                NETWORK_MODULES
            )
            check(
                "no network modules imported", not re.search(pat, src, re.M)
            )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    lines.append(
        "SELFTEST %s (%d failed)"
        % ("FAILED" if fails else "PASSED", len(fails))
    )
    return not fails, lines


# === window (Tkinter, v2.0.0 executive sidebar console) ===
def run_gui():
    try:
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox
    except ImportError:
        print(
            "Tkinter is not available in this Python. Use the command"
            " line instead:\n python fwaudit.py run --algosec <folder>"
            " --rfc <folder> --out <folder>"
        )
        return 2
    import queue
    import threading

    state_path = os.path.join(tool_dir(), "fwaudit_gui.json")
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, ValueError):
        state = {}

    root = tk.Tk()
    auth_cfg = load_auth()
    logged_in_user = {"name": ""}
    if auth_cfg["enabled"]:
        root.withdraw()
        login_win = tk.Toplevel(root)
        login_win.title("PolicyPulse — DXC Technology Sign In")
        sw, sh = login_win.winfo_screenwidth(), login_win.winfo_screenheight()
        login_win.geometry("%dx%d+0+0" % (sw, sh))
        try:
            login_win.state("zoomed")
        except Exception:
            pass
        login_win.minsize(820, 600)
        login_win.configure(bg="#0B1930")

        # Top & Bottom DXC Blue-to-Orange gradient bars
        def _mk_lgrad(parent_w):
            cv = tk.Canvas(parent_w, height=6, highlightthickness=0, bd=0)
            def _dg(ev=None):
                cv.delete("all")
                cw = max(cv.winfo_width(), 900)
                stps = 48
                for ii in range(stps):
                    tt = ii / float(stps - 1)
                    col = "#%02x%02x%02x" % (
                        int(0x4E + (0xFF - 0x4E) * tt),
                        int(0x86 + (0x7A - 0x86) * tt),
                        int(0xF7 + (0x45 - 0xF7) * tt),
                    )
                    cv.create_rectangle(ii * (cw / float(stps)), 0, (ii + 1) * (cw / float(stps)) + 1, 6, fill=col, outline="")
            cv.bind("<Configure>", _dg)
            _dg()
            return cv

        _mk_lgrad(login_win).pack(fill="x", side="top")
        _mk_lgrad(login_win).pack(fill="x", side="bottom")

        # Centered White Login Card
        card_wrap = tk.Frame(login_win, bg="#FFFFFF", bd=0, highlightbackground="#2563EB", highlightthickness=2)
        card_wrap.place(relx=0.5, rely=0.5, anchor="center", width=480)

        tk.Frame(card_wrap, bg="#FF6B35", height=5).pack(fill="x")
        lf = tk.Frame(card_wrap, bg="#FFFFFF", padx=36, pady=28)
        lf.pack(fill="both", expand=True)

        lgn_img = None
        try:
            lgn_img = tk.PhotoImage(data=DXC_LOGIN_LOGO_B64)
        except Exception:
            lgn_img = None
        if lgn_img is not None:
            lgn_lbl = tk.Label(lf, image=lgn_img, bg="#FFFFFF")
            lgn_lbl.image = lgn_img
            lgn_lbl.pack(pady=(0, 10))

        tk.Label(
            lf,
            text="PolicyPulse",
            bg="#FFFFFF",
            fg="#0B1930",
            font=("Segoe UI", 24, "bold"),
        ).pack()
        tk.Label(
            lf,
            text="ENTERPRISE FIREWALL AUDIT & GRC CONSOLE",
            bg="#FFFFFF",
            fg="#2563EB",
            font=("Segoe UI", 8, "bold"),
        ).pack(pady=(2, 18))

        tk.Frame(lf, bg="#E2E8F0", height=1).pack(fill="x", pady=(0, 16))

        tk.Label(lf, text="Username", bg="#FFFFFF", fg="#0B1930", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        u_var = tk.StringVar(value=state.get("operator", ""))
        u_ent = ttk.Entry(lf, textvariable=u_var, font=("Segoe UI", 10))
        u_ent.pack(fill="x", pady=(4, 12), ipady=4)

        tk.Label(lf, text="Password", bg="#FFFFFF", fg="#0B1930", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        p_var = tk.StringVar()
        p_ent = ttk.Entry(lf, textvariable=p_var, show="*", font=("Segoe UI", 10))
        p_ent.pack(fill="x", pady=(4, 6), ipady=4)

        err_var = tk.StringVar(value="")
        tk.Label(lf, textvariable=err_var, bg="#FFFFFF", fg="#DC2626", font=("Segoe UI", 8, "bold")).pack(
            anchor="w", pady=(2, 10)
        )
        ok_login = {"ok": False}

        def try_login(*_):
            if verify_auth(u_var.get(), p_var.get()):
                ok_login["ok"] = True
                logged_in_user["name"] = u_var.get().strip()
                login_win.destroy()
            else:
                err_var.set("Invalid username or password.")
                p_var.set("")
                p_ent.focus_set()

        bf_l = tk.Frame(lf, bg="#FFFFFF")
        bf_l.pack(fill="x", pady=(4, 12))
        tk.Button(
            bf_l, text="Sign In", command=try_login, bg="#FF6B35", fg="#FFFFFF",
            activebackground="#E55320", activeforeground="#FFFFFF",
            font=("Segoe UI", 10, "bold"), relief="flat", pady=8, cursor="hand2"
        ).pack(side="left", fill="x", expand=True, padx=(0, 6))
        tk.Button(
            bf_l, text="Exit", command=login_win.destroy, bg="#E2E8F0", fg="#0B1930",
            font=("Segoe UI", 10), relief="flat", padx=18, pady=8, cursor="hand2"
        ).pack(side="left")

        tk.Label(
            lf,
            text="DXC Technology • Built by Ganesh A  |  100% Offline • Zero Network",
            bg="#FFFFFF",
            fg="#64748B",
            font=("Segoe UI", 8),
        ).pack(pady=(6, 0))

        p_ent.bind("<Return>", try_login)
        u_ent.bind("<Return>", lambda *_: p_ent.focus_set())
        (p_ent if u_var.get().strip() else u_ent).focus_set()
        root.wait_window(login_win)
        if not ok_login["ok"]:
            root.destroy()
            return 0
        root.deiconify()

    root.title("PolicyPulse — DXC Firewall Audit & Compliance Console v%s" % VERSION)
    root.geometry("1220x790")
    root.minsize(1020, 680)
    root.configure(bg="#F0F4FA")

    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")
    style.configure("TFrame", background="#F0F4FA")
    style.configure("Card.TFrame", background="#FFFFFF")
    style.configure("TLabel", background="#F0F4FA", foreground="#0B1930", font=("Segoe UI", 9))
    style.configure("Card.TLabel", background="#FFFFFF", foreground="#0B1930", font=("Segoe UI", 9))
    style.configure("TCheckbutton", background="#FFFFFF", foreground="#0B1930", font=("Segoe UI", 9))
    style.configure("TRadiobutton", background="#FFFFFF", foreground="#0B1930", font=("Segoe UI", 9))
    style.configure(
        "Treeview",
        background="#FFFFFF",
        fieldbackground="#FFFFFF",
        foreground="#0B1930",
        rowheight=25,
        font=("Segoe UI", 9),
    )
    style.configure(
        "Treeview.Heading",
        background="#1E3A8A",
        foreground="#FFFFFF",
        font=("Segoe UI", 9, "bold"),
        padding=[6, 5],
    )
    style.map("Treeview.Heading", background=[("active", "#2563EB")])
    style.configure(
        "DXC.TButton",
        background="#FF6B35",
        foreground="#FFFFFF",
        font=("Segoe UI", 9, "bold"),
        padding=[14, 6],
    )
    style.map("DXC.TButton", background=[("active", "#E55320"), ("disabled", "#CBD5E1")])
    style.configure(
        "Sec.TButton",
        background="#1E3A8A",
        foreground="#FFFFFF",
        font=("Segoe UI", 9, "bold"),
        padding=[10, 5],
    )
    style.map("Sec.TButton", background=[("active", "#2563EB"), ("disabled", "#CBD5E1")])

    # --- Top Executive Header ---
    hdr_bar = tk.Frame(root, bg="#0B1930", height=72)
    hdr_bar.pack(fill="x")
    hdr_bar.pack_propagate(False)

    grad_bar = tk.Canvas(root, height=5, highlightthickness=0, bd=0)
    grad_bar.pack(fill="x")

    def _draw_grad(event=None):
        grad_bar.delete("all")
        w = max(grad_bar.winfo_width(), 1000)
        steps = 48
        r1, g1, b1 = 0x4E, 0x86, 0xF7
        r2, g2, b2 = 0xFF, 0x7A, 0x45
        sw = w / float(steps)
        for i in range(steps):
            t = i / float(steps - 1)
            col = "#%02x%02x%02x" % (
                int(r1 + (r2 - r1) * t),
                int(g1 + (g2 - g1) * t),
                int(b1 + (b2 - b1) * t),
            )
            grad_bar.create_rectangle(i * sw, 0, (i + 1) * sw + 1, 5, fill=col, outline="")

    grad_bar.bind("<Configure>", _draw_grad)
    _draw_grad()

    logo_loaded = None
    for lname in ("dxc_logo.png", "dxc_logo.gif"):
        lp = os.path.join(tool_dir(), lname)
        if os.path.isfile(lp):
            try:
                logo_loaded = tk.PhotoImage(file=lp)
                break
            except Exception:
                logo_loaded = None
    if logo_loaded is None:
        try:
            logo_loaded = tk.PhotoImage(data=DXC_LOGO_B64)
        except Exception:
            logo_loaded = None

    if logo_loaded is not None:
        logo_card = tk.Frame(hdr_bar, bg="#FFFFFF", padx=8, pady=4)
        logo_card.pack(side="left", padx=(16, 14), pady=7)
        logo_lbl = tk.Label(logo_card, image=logo_loaded, bg="#FFFFFF")
        logo_lbl.image = logo_loaded
        logo_lbl.pack()

    title_box = tk.Frame(hdr_bar, bg="#0B1930")
    title_box.pack(side="left", pady=10)
    tk.Label(
        title_box,
        text="DXC TECHNOLOGY  •  IT SECURITY & GRC",
        bg="#0B1930",
        fg="#FF7A45",
        font=("Segoe UI", 9, "bold"),
    ).pack(anchor="w")
    tk.Label(
        title_box,
        text="PolicyPulse  •  Firewall Change Audit & GRC",
        bg="#0B1930",
        fg="#FFFFFF",
        font=("Segoe UI", 15, "bold"),
    ).pack(anchor="w")

    status_pill = tk.Label(
        hdr_bar,
        text="READY",
        bg="#2563EB",
        fg="#FFFFFF",
        font=("Segoe UI", 9, "bold"),
        padx=14,
        pady=5,
    )
    status_pill.pack(side="right", padx=16)

    # --- State variables ---
    var = dict(
        (k, tk.StringVar(value=state.get(k, "")))
        for k in ("algosec", "rfc", "out", "smax", "operator")
    )
    if not var["out"].get():
        var["out"].set(os.path.join(tool_dir(), "output"))
    if logged_in_user["name"]:
        var["operator"].set(logged_in_user["name"])
    elif not var["operator"].get():
        var["operator"].set(default_operator())
    date_var = tk.StringVar(value="")

    op_badge_var = tk.StringVar(value="Operator: %s" % (var["operator"].get() or "Not Set"))
    var["operator"].trace_add(
        "write", lambda *_: op_badge_var.set("Operator: %s" % (var["operator"].get().strip() or "Not Set"))
    )
    tk.Label(
        hdr_bar,
        textvariable=op_badge_var,
        bg="#162D54",
        fg="#D8E6FB",
        font=("Segoe UI", 9),
        padx=12,
        pady=5,
    ).pack(side="right", padx=4)

    # --- Body: Left Sidebar + Main Workspace ---
    body = tk.Frame(root, bg="#F0F4FA")
    body.pack(fill="both", expand=True)

    sidebar = tk.Frame(body, bg="#0F2547", width=162)
    sidebar.pack(side="left", fill="y")
    sidebar.pack_propagate(False)

    workspace = tk.Frame(body, bg="#F0F4FA", padx=10, pady=8)
    workspace.pack(side="left", fill="both", expand=True)
    workspace.rowconfigure(0, weight=1)
    workspace.columnconfigure(0, weight=1)

    pages = {}
    nav_items = [
        ("dash", "Dashboard", "📊"),
        ("results", "Audit Results", "🔍"),
        ("comp", "Compliance", "🛡"),
        ("master", "Consolidator", "📦"),
        ("jobs", "Audit History", "🕒"),
        ("cfg", "Settings", "⚙"),
    ]
    for key, _, _ in nav_items:
        fr = tk.Frame(workspace, bg="#F0F4FA")
        fr.grid(row=0, column=0, sticky="nsew")
        pages[key] = fr

    nav_btns = {}
    nav_bars = {}
    sb_state = {"collapsed": False}

    def select_page(key):
        pages[key].tkraise()
        for k, btn in nav_btns.items():
            if k == key:
                btn.configure(bg="#1A3A6E", fg="#FFFFFF")
                nav_bars[k].configure(bg="#FF6B35")
            else:
                btn.configure(bg="#0F2547", fg="#CBD5E1")
                nav_bars[k].configure(bg="#0F2547")

    sb_top = tk.Frame(sidebar, bg="#0F2547")
    sb_top.pack(fill="x", padx=8, pady=(10, 6))
    sb_title_lbl = tk.Label(
        sb_top, text="MENU", bg="#0F2547", fg="#64748B", font=("Segoe UI", 8, "bold")
    )
    sb_title_lbl.pack(side="left", padx=4)

    def toggle_sidebar():
        sb_state["collapsed"] = not sb_state["collapsed"]
        if sb_state["collapsed"]:
            sidebar.configure(width=48)
            sb_title_lbl.pack_forget()
            sb_foot.pack_forget()
            for k, lbl, ico in nav_items:
                nav_btns[k].configure(text=ico, anchor="center", padx=0)
        else:
            sidebar.configure(width=162)
            sb_title_lbl.pack(side="left", padx=4)
            sb_foot.pack(side="bottom", fill="x")
            for k, lbl, ico in nav_items:
                nav_btns[k].configure(text=" %s  %s" % (ico, lbl), anchor="w", padx=8)

    tk.Button(
        sb_top, text="☰", bg="#162D54", fg="#FFFFFF", relief="flat", bd=0,
        font=("Segoe UI", 10, "bold"), width=3, cursor="hand2", command=toggle_sidebar,
    ).pack(side="right")

    for key, label, icon in nav_items:
        row_f = tk.Frame(sidebar, bg="#0F2547")
        row_f.pack(fill="x", pady=1)
        bar = tk.Frame(row_f, bg="#0F2547", width=4)
        bar.pack(side="left", fill="y")
        btn = tk.Button(
            row_f,
            text=" %s  %s" % (icon, label),
            anchor="w",
            bg="#0F2547",
            fg="#CBD5E1",
            activebackground="#1A3A6E",
            activeforeground="#FFFFFF",
            relief="flat",
            bd=0,
            font=("Segoe UI", 9, "bold"),
            padx=8,
            pady=8,
            cursor="hand2",
            command=lambda k=key: select_page(k),
        )
        btn.pack(side="left", fill="x", expand=True)
        nav_btns[key] = btn
        nav_bars[key] = bar

    sb_foot = tk.Frame(sidebar, bg="#0B1930", padx=10, pady=10)
    sb_foot.pack(side="bottom", fill="x")
    tk.Label(
        sb_foot,
        text="DXC Technology\nBuilt by Ganesh A",
        bg="#0B1930",
        fg="#FF7A45",
        font=("Segoe UI", 8, "bold"),
        justify="left",
    ).pack(anchor="w")
    tk.Label(
        sb_foot,
        text="v%s • Offline" % VERSION,
        bg="#0B1930",
        fg="#94A3B8",
        font=("Segoe UI", 8),
        justify="left",
    ).pack(anchor="w", pady=(3, 0))

    def make_card(parent, title=None, compact=False):
        outer = tk.Frame(parent, bg="#FFFFFF", bd=1, relief="solid", highlightbackground="#D5E2F4", highlightthickness=1)
        if title:
            hdr_c = tk.Frame(outer, bg="#F8FAFC", height=30)
            hdr_c.pack(fill="x")
            tk.Label(
                hdr_c, text=title, bg="#F8FAFC", fg="#1E3A8A", font=("Segoe UI", 9, "bold"), padx=10, pady=5
            ).pack(side="left")
            tk.Frame(outer, bg="#E2E8F0", height=1).pack(fill="x")
        pad_xy = (8, 5) if compact else (12, 10)
        inner = tk.Frame(outer, bg="#FFFFFF", padx=pad_xy[0], pady=pad_xy[1])
        inner.pack(fill="both", expand=True)
        return outer, inner

    def make_sortable(tree, cols):
        sort_state = {"col": None, "rev": False}

        def _sort_key(val):
            s = str(val or "").strip()
            if s.isdigit():
                return (0, int(s), "")
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%d-%b-%Y", "%d-%m-%Y", "%Y-%m-%d"):
                try:
                    return (1, datetime.datetime.strptime(s.split(" [")[0], fmt).timestamp(), "")
                except ValueError:
                    continue
            return (2, 0, s.lower())

        def sort_by(col):
            rev = (not sort_state["rev"]) if sort_state["col"] == col else False
            sort_state["col"], sort_state["rev"] = col, rev
            items = [(tree.set(iid, col), iid) for iid in tree.get_children("")]
            items.sort(key=lambda x: _sort_key(x[0]), reverse=rev)
            for idx, (_, iid) in enumerate(items):
                tree.move(iid, "", idx)
            for c in cols:
                arrow = (" ▼" if rev else " ▲") if c == col else ""
                tree.heading(c, text=c + arrow, command=lambda c=c: sort_by(c))

        for c in cols:
            tree.heading(c, text=c, command=lambda c=c: sort_by(c))

    # =========================================================================
    # PAGE 1: DASHBOARD & RUN
    # =========================================================================
    p_dash = pages["dash"]
    p_dash.columnconfigure(0, weight=1)

    # 1. KPI Strip
    kpi_strip = tk.Frame(p_dash, bg="#F0F4FA")
    kpi_strip.grid(row=0, column=0, sticky="ew", pady=(0, 10))
    kpi_vars = {}
    kpi_defs = [
        ("total", "TOTAL RULES", "#2563EB", "#EFF6FF"),
        ("yes", "PIR DEVIATIONS (YES)", "#DC2626", "#FEF2F2"),
        ("no", "COMPLIANT (NO)", "#16A34A", "#F0FDF4"),
        ("review", "PENDING REVIEW", "#D97706", "#FFFBEB"),
        ("risky", "HIGH-RISK RULES", "#FF6B35", "#FFF7ED"),
    ]
    for idx, (key, title, accent, tint) in enumerate(kpi_defs):
        kpi_strip.columnconfigure(idx, weight=1)
        card = tk.Frame(kpi_strip, bg="#FFFFFF", bd=0, highlightbackground="#D5E2F4", highlightthickness=1)
        card.grid(row=0, column=idx, sticky="ew", padx=(0 if idx == 0 else 5, 0 if idx == 4 else 5))
        tk.Frame(card, bg=accent, height=4).pack(fill="x")
        cbody = tk.Frame(card, bg=tint, padx=12, pady=8)
        cbody.pack(fill="both", expand=True)
        kpi_vars[key] = tk.StringVar(value="—")
        tk.Label(cbody, text=title, bg=tint, fg="#475569", font=("Segoe UI", 8, "bold")).pack(anchor="w")
        tk.Label(cbody, textvariable=kpi_vars[key], bg=tint, fg=accent, font=("Segoe UI", 20, "bold")).pack(anchor="w")

    # 2. Compliance Gauge + Missing RFC Card
    gauge_card, gauge_in = make_card(p_dash)
    gauge_card.grid(row=1, column=0, sticky="ew", pady=(0, 10))
    gauge_in.columnconfigure(0, weight=1)
    comp_lbl_var = tk.StringVar(value="Compliance Overview: Run an audit to inspect rule coverage & hygiene")
    tk.Label(gauge_in, textvariable=comp_lbl_var, bg="#FFFFFF", fg="#0B1930", font=("Segoe UI", 9, "bold")).grid(
        row=0, column=0, sticky="w"
    )
    missing_rfcs_holder = {"list": []}
    miss_row = tk.Frame(gauge_in, bg="#FFFFFF")
    miss_row.grid(row=0, column=1, sticky="e")
    miss_lbl_var = tk.StringVar(value="Missing RFC Sheets: —")
    tk.Label(miss_row, textvariable=miss_lbl_var, bg="#FFFFFF", fg="#B45309", font=("Segoe UI", 8, "bold")).pack(
        side="left", padx=(0, 8)
    )

    def copy_missing_rfcs():
        items = missing_rfcs_holder["list"]
        if not items:
            return
        txt = "\n".join("RFC" + n for n in items)
        root.clipboard_clear()
        root.clipboard_append(txt)
        messagebox.showinfo("Copied", "Copied %d missing RFC(s) to clipboard:\n%s" % (len(items), txt))

    def copy_smax_downloader():
        items = missing_rfcs_holder["list"]
        if not items:
            return
        cur_cfg = load_config()
        s_cfg = cur_cfg.get("smax", {})
        script = build_smax_browser_script(
            items,
            s_cfg.get("base_url") or CONFIG["smax"]["base_url"],
            s_cfg.get("tenant_id") or CONFIG["smax"]["tenant_id"],
        )
        root.clipboard_clear()
        root.clipboard_append(script)
        messagebox.showinfo(
            "SMAX Downloader Copied",
            "Copied SMAX batch downloader for %d missing RFC(s).\n\n"
            "How to use:\n"
            "1. Open your logged-in SMAX tab in Edge/Chrome.\n"
            "2. Press F12 -> Console, paste (Ctrl+V), and press Enter.\n"
            "3. Move the downloaded RFC_*.xlsx files into your RFC Port Sheets Folder and click Run Audit."
            % len(items),
        )

    smax_session_creds = {"user": "", "pw": ""}

    def fetch_missing_from_smax():
        items = missing_rfcs_holder["list"]
        if not items:
            return
        rfc_dir = var["rfc"].get().strip()
        if not rfc_dir:
            rfc_dir = filedialog.askdirectory(title="Select RFC Port Sheets Folder to Save Downloaded RFCs")
            if not rfc_dir:
                return
            var["rfc"].set(rfc_dir)
            refresh_badges()
        sp = os.path.join(tool_dir(), "smax_fetch.py")
        if not os.path.isfile(sp):
            messagebox.showerror(
                "smax_fetch.py Not Found",
                "Place smax_fetch.py in the same folder as fwaudit.py:\n%s" % tool_dir(),
            )
            return

        def _launch_fetch(u, p):
            smax_fetch_btn.configure(state="disabled")
            logbox.configure(state="normal")
            logbox.insert("end", "Fetching %d missing RFC(s) from SMAX into %s...\n" % (len(items), rfc_dir))
            logbox.see("end")
            logbox.configure(state="disabled")

            def _bg():
                import subprocess
                cur_cfg = load_config()
                cmd = smax_fetch_command(items, rfc_dir, cur_cfg, u, sp)
                try:
                    proc = subprocess.Popen(
                        cmd,
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                    )
                    out_txt, _ = proc.communicate(input=p + "\n", timeout=300)
                    for ln in (out_txt or "").splitlines():
                        q.put(("log", ln))
                    q.put(("smax_done", (proc.returncode, rfc_dir)))
                except Exception as ex:
                    q.put(("log", "SMAX fetch error: %s" % ex))
                    q.put(("smax_done", (-1, rfc_dir)))

            threading.Thread(target=_bg, daemon=True).start()

        if smax_session_creds["user"] and smax_session_creds["pw"]:
            _launch_fetch(smax_session_creds["user"], smax_session_creds["pw"])
            return

        dlg = tk.Toplevel(root)
        dlg.title("SMAX Login — Fetch Missing RFCs")
        dlg.transient(root)
        dlg.grab_set()
        dlg.resizable(False, False)
        frm = tk.Frame(dlg, bg="#FFFFFF", padx=16, pady=14)
        frm.pack(fill="both", expand=True)
        tk.Label(frm, text="Download %d missing RFC(s) from SMAX" % len(items), bg="#FFFFFF", fg="#0B1930", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        tk.Label(frm, text="SMAX Username:", bg="#FFFFFF").grid(row=1, column=0, sticky="w", pady=3)
        v_su = tk.StringVar(value=smax_session_creds["user"])
        e_su = ttk.Entry(frm, textvariable=v_su, width=28)
        e_su.grid(row=1, column=1, sticky="ew", padx=(8, 0), pady=3)
        tk.Label(frm, text="SMAX Password:", bg="#FFFFFF").grid(row=2, column=0, sticky="w", pady=3)
        v_sp = tk.StringVar()
        e_sp = ttk.Entry(frm, textvariable=v_sp, show="*", width=28)
        e_sp.grid(row=2, column=1, sticky="ew", padx=(8, 0), pady=3)
        v_rem = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm, text="Keep in memory for this session only", variable=v_rem).grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 8))

        def _go(*_):
            u, p = v_su.get().strip(), v_sp.get()
            if not u or not p:
                messagebox.showwarning("Missing Credentials", "Enter both SMAX username and password.", parent=dlg)
                return
            if v_rem.get():
                smax_session_creds["user"], smax_session_creds["pw"] = u, p
            dlg.destroy()
            _launch_fetch(u, p)

        b_row = tk.Frame(frm, bg="#FFFFFF")
        b_row.grid(row=4, column=0, columnspan=2, sticky="e")
        ttk.Button(b_row, text="Cancel", command=dlg.destroy).pack(side="left", padx=(0, 6))
        ttk.Button(b_row, text="Download Missing RFCs", style="DXC.TButton", command=_go).pack(side="left")
        e_sp.bind("<Return>", _go)
        (e_sp if v_su.get() else e_su).focus_set()

    copy_miss_btn = ttk.Button(miss_row, text="Copy Missing RFCs", state="disabled", command=copy_missing_rfcs)
    copy_miss_btn.pack(side="left", padx=(0, 4))
    smax_dl_btn = ttk.Button(miss_row, text="Copy SMAX Downloader", state="disabled", command=copy_smax_downloader)
    smax_dl_btn.pack(side="left", padx=(0, 4))
    smax_fetch_btn = ttk.Button(miss_row, text="Fetch from SMAX", style="DXC.TButton", state="disabled", command=fetch_missing_from_smax)
    smax_fetch_btn.pack(side="left")

    comp_canvas = tk.Canvas(gauge_in, height=14, bg="#E2E8F0", highlightthickness=0)
    comp_canvas.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 0))

    def draw_compliance_bar(yes_n=0, no_n=0, rev_n=0, na_n=0):
        comp_canvas.delete("all")
        tot_n = yes_n + no_n + rev_n + na_n
        if not tot_n:
            return
        w = max(comp_canvas.winfo_width(), 700)
        x = 0.0
        for cnt, col in ((no_n, "#16A34A"), (yes_n, "#DC2626"), (rev_n, "#F59E0B"), (na_n, "#94A3B8")):
            if cnt:
                seg_w = w * (cnt / float(tot_n))
                comp_canvas.create_rectangle(x, 0, x + seg_w, 14, fill=col, outline="")
                x += seg_w
        pct_ok = int(round(100.0 * no_n / tot_n))
        comp_lbl_var.set(
            "Compliance Overview: %d%% Approved (%d NO | %d YES Deviations | %d REVIEW | %d N/A)"
            % (pct_ok, no_n, yes_n, rev_n, na_n)
        )

    # 3. Audit Inputs & Actions Card
    inp_card, inp_in = make_card(p_dash, "Audit Workspace & Input Sources")
    inp_card.grid(row=2, column=0, sticky="ew", pady=(0, 10))
    inp_in.columnconfigure(1, weight=1)

    badges = {
        "algosec": tk.StringVar(value="Select folder"),
        "rfc": tk.StringVar(value="Optional (needed for PIR)"),
        "out": tk.StringVar(value="Output folder"),
        "smax": tk.StringVar(value="Optional"),
    }

    def refresh_badges(*_):
        ap = var["algosec"].get().strip()
        if ap and os.path.isdir(ap):
            n = len(discover_reports([ap]))
            badges["algosec"].set("● %d .xlsx file(s)" % n if n else "○ No .xlsx found")
        elif ap:
            badges["algosec"].set("✕ Folder not found")
        else:
            badges["algosec"].set("○ Select folder")

        rp = var["rfc"].get().strip()
        if rp and os.path.isdir(rp):
            n = sum(
                1 for f in os.listdir(rp)
                if _is_rfc_excel_file(os.path.join(rp, f))
            )
            badges["rfc"].set("● %d RFC file(s)" % n)
        elif rp:
            badges["rfc"].set("✕ Folder not found")
        else:
            badges["rfc"].set("○ Optional")

        sp = var["smax"].get().strip()
        if sp and os.path.exists(sp):
            badges["smax"].set("● " + os.path.basename(sp)[:20])
        elif sp:
            badges["smax"].set("✕ File not found")
        else:
            badges["smax"].set("○ Optional")

    for k in ("algosec", "rfc", "smax"):
        var[k].trace_add("write", refresh_badges)

    def pick_dir(k):
        d = filedialog.askdirectory(initialdir=var[k].get() or tool_dir())
        if d:
            var[k].set(d)

    def pick_file(k):
        f = filedialog.askopenfilename(filetypes=[("Excel or CSV", "*.xlsx *.xlsm *.csv")])
        if f:
            var[k].set(f)

    tk.Label(inp_in, text="Operator User ID (PREPARED BY)", bg="#FFFFFF", fg="#0B1930", font=("Segoe UI", 9, "bold")).grid(
        row=0, column=0, sticky="w", pady=3
    )
    op_row = tk.Frame(inp_in, bg="#FFFFFF")
    op_row.grid(row=0, column=1, columnspan=3, sticky="w", padx=8, pady=3)
    ttk.Entry(op_row, textvariable=var["operator"], width=26).pack(side="left")
    tk.Label(op_row, text="    Report Date (DD-MM-YYYY, optional):", bg="#FFFFFF", fg="#475569", font=("Segoe UI", 9)).pack(side="left")
    ttk.Entry(op_row, textvariable=date_var, width=14).pack(side="left", padx=6)

    for i, (label, k, fn) in enumerate(
        [
            ("AlgoSec Reports Folder", "algosec", pick_dir),
            ("RFC Port Sheets Folder", "rfc", pick_dir),
            ("Output Folder", "out", pick_dir),
            ("SMAX Export (optional)", "smax", pick_file),
        ],
        1,
    ):
        tk.Label(inp_in, text=label, bg="#FFFFFF", fg="#0B1930", font=("Segoe UI", 9)).grid(
            row=i, column=0, sticky="w", pady=3
        )
        ttk.Entry(inp_in, textvariable=var[k]).grid(row=i, column=1, sticky="ew", padx=8, pady=3)
        ttk.Button(inp_in, text="Browse", width=9, command=lambda k=k, fn=fn: fn(k)).grid(row=i, column=2, padx=4, pady=3)
        tk.Label(inp_in, textvariable=badges[k], width=22, bg="#FFFFFF", fg="#2563EB", font=("Segoe UI", 8, "bold"), anchor="w").grid(
            row=i, column=3, sticky="w", padx=6
        )

    btn_bar = tk.Frame(inp_in, bg="#FFFFFF")
    btn_bar.grid(row=5, column=0, columnspan=4, sticky="ew", pady=(10, 2))
    last_outputs = {"daily": None, "audit": None, "folder": None}
    last_ctx_holder = {"ctx": None}

    def _open_path(p):
        if p and os.path.exists(p) and hasattr(os, "startfile"):
            os.startfile(p)

    run_btn = ttk.Button(btn_bar, text="▶  Run Audit", style="DXC.TButton")
    run_btn.pack(side="left", padx=(0, 8))
    daily_btn = ttk.Button(
        btn_bar, text="Open Daily Report", state="disabled", command=lambda: _open_path(last_outputs["daily"])
    )
    daily_btn.pack(side="left", padx=3)
    audit_btn = ttk.Button(
        btn_bar, text="Open Audit Workbook", state="disabled", command=lambda: _open_path(last_outputs["audit"])
    )
    audit_btn.pack(side="left", padx=3)

    def export_html_ui():
        c = last_ctx_holder["ctx"]
        if c is None:
            return
        out_p = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Report", "*.html")],
            initialfile="DXC_Firewall_Audit_Summary_%s.html" % c.report_date.strftime("%d-%m-%Y"),
        )
        if not out_p:
            return
        export_html_summary(c, out_p)
        _open_path(out_p)
        messagebox.showinfo("HTML Exported", "Executive Summary saved to:\n%s" % out_p)

    html_btn = ttk.Button(btn_bar, text="Executive HTML", state="disabled", command=export_html_ui)
    html_btn.pack(side="left", padx=3)

    def export_cleanup_ui():
        c = last_ctx_holder["ctx"]
        if c is None:
            return
        out_p = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel Workbook", "*.xlsx")],
            initialfile="Expiry_Cleanup_Report_%s.xlsx" % c.report_date.strftime("%d-%m-%Y"),
        )
        if not out_p:
            return
        export_expiry_cleanup_xlsx(c, out_p)
        _open_path(out_p)
        messagebox.showinfo("Exported", "Owner-grouped Expiry Cleanup report saved to:\n%s" % out_p)

    cleanup_btn = ttk.Button(btn_bar, text="Expiry Cleanup (.xlsx)", state="disabled", command=export_cleanup_ui)
    cleanup_btn.pack(side="left", padx=3)
    ttk.Button(
        btn_bar, text="Open Output", command=lambda: _open_path(last_outputs["folder"] or var["out"].get().strip())
    ).pack(side="left", padx=3)

    # 4. Bottom Split: Per-Firewall Breakdown + Console
    bot_split = tk.Frame(p_dash, bg="#F0F4FA")
    bot_split.grid(row=3, column=0, sticky="nsew")
    p_dash.rowconfigure(3, weight=1)
    bot_split.columnconfigure(0, weight=1)
    bot_split.columnconfigure(1, weight=1)
    bot_split.rowconfigure(0, weight=1)

    fw_card, fw_in = make_card(bot_split, "Firewall-Wise Audit Summary")
    fw_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
    fw_cols = ("Firewall Tab", "Rules", "YES", "NO", "REVIEW", "Risky")
    fw_tree = ttk.Treeview(fw_in, columns=fw_cols, show="headings", height=8)
    for c, w in zip(fw_cols, (125, 55, 50, 50, 60, 55)):
        fw_tree.column(c, width=w, anchor="w" if c == "Firewall Tab" else "center")
    make_sortable(fw_tree, fw_cols)
    fw_y = ttk.Scrollbar(fw_in, orient="vertical", command=fw_tree.yview)
    fw_tree.configure(yscrollcommand=fw_y.set)
    fw_tree.pack(side="left", fill="both", expand=True)
    fw_y.pack(side="right", fill="y")

    log_card, log_in = make_card(bot_split, "Audit Execution Log")
    log_card.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
    logbox = tk.Text(
        log_in, height=8, wrap="word", state="disabled", font=("Consolas", 9),
        bg="#0B1930", fg="#E2E8F0", insertbackground="#FFFFFF", relief="flat", padx=8, pady=6
    )
    log_scroll = ttk.Scrollbar(log_in, orient="vertical", command=logbox.yview)
    logbox.configure(yscrollcommand=log_scroll.set)
    logbox.pack(side="left", fill="both", expand=True)
    log_scroll.pack(side="right", fill="y")

    # =========================================================================
    # PAGE 2: AUDIT RESULTS
    # =========================================================================
    p_res = pages["results"]
    flt_card, flt_in = make_card(p_res, title=None, compact=True)
    flt_card.pack(fill="x", pady=(0, 5))

    flt_bar = tk.Frame(flt_in, bg="#FFFFFF")
    flt_bar.pack(fill="x", pady=(0, 4))
    tk.Label(flt_bar, text="PIR:", bg="#FFFFFF", font=("Segoe UI", 8, "bold")).pack(side="left")
    flt_status = tk.StringVar(value="All")
    flt_combo = ttk.Combobox(
        flt_bar,
        textvariable=flt_status,
        values=["All", "YES", "NO", "REVIEW", "N/A", "Added", "Edited", "Removed", "Risky Only", "Expired Only", "Disabled Only", "Blank Description", "Deny / Drop Only"],
        state="readonly",
        width=14,
    )
    flt_combo.pack(side="left", padx=(3, 8))

    tk.Label(flt_bar, text="In:", bg="#FFFFFF", font=("Segoe UI", 8, "bold")).pack(side="left")
    flt_field = tk.StringVar(value="All Fields")
    flt_field_combo = ttk.Combobox(
        flt_bar,
        textvariable=flt_field,
        values=["All Fields", "Source", "Destination", "Source & Destination", "Service", "RFC Match", "Date", "PIR ISSUE", "Rule Name", "Tab", "Asset Owner"],
        state="readonly",
        width=12,
    )
    flt_field_combo.pack(side="left", padx=(3, 4))

    flt_search = tk.StringVar(value="")
    flt_search_ent = ttk.Entry(flt_bar, textvariable=flt_search, width=22)
    flt_search_ent.pack(side="left", padx=3)

    dt_bar = tk.Frame(flt_in, bg="#FFFFFF")
    dt_bar.pack(fill="x", pady=0)
    time_choices = ["%02d:%02d" % (h, m) for h in range(24) for m in (0, 30)] + ["23:59"]
    flt_from_date = tk.StringVar(value="")
    flt_from_time = tk.StringVar(value="00:00")
    flt_to_date = tk.StringVar(value="")
    flt_to_time = tk.StringVar(value="23:59")

    def open_cal_picker(target_var):
        top = tk.Toplevel(root)
        top.title("Select Date")
        top.resizable(False, False)
        top.configure(bg="#F0F4FA")
        try:
            cur_d = datetime.datetime.strptime(target_var.get().strip(), "%Y-%m-%d").date()
        except ValueError:
            cur_d = datetime.date.today()
        st_cal = {"y": cur_d.year, "m": cur_d.month}
        hdr_c = tk.Frame(top, bg="#0B1930", padx=8, pady=6)
        hdr_c.pack(fill="x")
        lbl_ym = tk.Label(hdr_c, text="", bg="#0B1930", fg="#FFFFFF", font=("Segoe UI", 10, "bold"), width=14)
        grid_c = tk.Frame(top, bg="#F0F4FA", padx=8, pady=8)

        def render_cal():
            for w in grid_c.winfo_children():
                w.destroy()
            lbl_ym.config(text="%s %d" % (calendar.month_abbr[st_cal["m"]], st_cal["y"]))
            for ci, dn in enumerate(("Mo", "Tu", "We", "Th", "Fr", "Sa", "Su")):
                tk.Label(grid_c, text=dn, bg="#F0F4FA", fg="#1E3A8A", font=("Segoe UI", 8, "bold"), width=3).grid(row=0, column=ci)
            for ri, week in enumerate(calendar.monthcalendar(st_cal["y"], st_cal["m"]), 1):
                for ci, day in enumerate(week):
                    if day == 0:
                        continue
                    d_str = "%04d-%02d-%02d" % (st_cal["y"], st_cal["m"], day)
                    tk.Button(
                        grid_c, text=str(day), width=3, bg="#FFFFFF", fg="#0B1930", relief="flat",
                        command=lambda ds=d_str: (target_var.set(ds), top.destroy()),
                    ).grid(row=ri, column=ci, padx=1, pady=1)

        def shift_m(delta):
            m, y = st_cal["m"] + delta, st_cal["y"]
            if m < 1:
                m, y = 12, y - 1
            elif m > 12:
                m, y = 1, y + 1
            st_cal["m"], st_cal["y"] = m, y
            render_cal()

        tk.Button(hdr_c, text="<", command=lambda: shift_m(-1), bg="#FF6B35", fg="#FFFFFF", relief="flat", width=3).pack(side="left")
        lbl_ym.pack(side="left", expand=True)
        tk.Button(hdr_c, text=">", command=lambda: shift_m(1), bg="#FF6B35", fg="#FFFFFF", relief="flat", width=3).pack(side="right")
        grid_c.pack()
        render_cal()

    tk.Label(dt_bar, text="From:", bg="#FFFFFF", font=("Segoe UI", 8, "bold")).pack(side="left")
    from_date_cb = ttk.Combobox(dt_bar, textvariable=flt_from_date, values=[], width=10)
    from_date_cb.pack(side="left", padx=(3, 1))
    ttk.Button(dt_bar, text="Cal", width=3, command=lambda: open_cal_picker(flt_from_date)).pack(side="left", padx=(0, 2))
    from_time_cb = ttk.Combobox(dt_bar, textvariable=flt_from_time, values=time_choices, width=5)
    from_time_cb.pack(side="left", padx=(0, 8))

    tk.Label(dt_bar, text="To:", bg="#FFFFFF", font=("Segoe UI", 8, "bold")).pack(side="left")
    to_date_cb = ttk.Combobox(dt_bar, textvariable=flt_to_date, values=[], width=10)
    to_date_cb.pack(side="left", padx=(3, 1))
    ttk.Button(dt_bar, text="Cal", width=3, command=lambda: open_cal_picker(flt_to_date)).pack(side="left", padx=(0, 2))
    to_time_cb = ttk.Combobox(dt_bar, textvariable=flt_to_time, values=time_choices, width=5)
    to_time_cb.pack(side="left", padx=(0, 6))

    flt_count_var = tk.StringVar(value="0 rules")
    tk.Label(flt_bar, textvariable=flt_count_var, bg="#FFFFFF", fg="#1E3A8A", font=("Segoe UI", 8, "bold")).pack(side="right", padx=(6, 0))

    res_card, res_in = make_card(p_res, title=None, compact=True)
    res_card.pack(fill="both", expand=True)

    res_cols = (
        "Tab", "Rule Name", "RFC Match", "Date", "Source", "Destination",
        "Service", "PIR ISSUE", "Risky", "Expiry", "Asset Owner", "Detail",
    )
    res_col_idx = dict((c, i) for i, c in enumerate(res_cols))
    tree_wrap = tk.Frame(res_in, bg="#FFFFFF")
    tree_wrap.pack(fill="both", expand=True)
    res_tree = ttk.Treeview(tree_wrap, columns=res_cols, show="headings")
    res_widths = {
        "Tab": 85, "Rule Name": 150, "RFC Match": 100, "Date": 125,
        "Source": 170, "Destination": 170, "Service": 130, "PIR ISSUE": 80,
        "Risky": 75, "Expiry": 105, "Asset Owner": 150, "Detail": 260,
    }
    for c in res_cols:
        res_tree.column(c, width=res_widths[c], anchor="w")
    make_sortable(res_tree, res_cols)
    res_tree.tag_configure("YES", background="#FEE2E2")
    res_tree.tag_configure("NO", background="#DCFCE7")
    res_tree.tag_configure("REVIEW", background="#FEF3C7")
    res_tree.tag_configure("N/A", background="#F1F5F9")
    rs_y = ttk.Scrollbar(tree_wrap, orient="vertical", command=res_tree.yview)
    rs_x = ttk.Scrollbar(tree_wrap, orient="horizontal", command=res_tree.xview)
    res_tree.configure(yscrollcommand=rs_y.set, xscrollcommand=rs_x.set)
    rs_y.pack(side="right", fill="y")
    rs_x.pack(side="bottom", fill="x")
    res_tree.pack(side="left", fill="both", expand=True)

    cached_results = []
    filtered_results = []
    res_iid_uid = {}

    def populate_results(*_):
        for item in res_tree.get_children():
            res_tree.delete(item)
        filtered_results.clear()
        res_iid_uid.clear()
        want = flt_status.get()
        field_name = flt_field.get()
        qtxt = flt_search.get().strip().lower()

        def _bound_dt(d_str, t_str, default_hm):
            ds = d_str.strip()
            if not ds:
                return None
            ts = (t_str.strip() or default_hm)[:5]
            for fmt in ("%Y-%m-%d %H:%M", "%d-%m-%Y %H:%M", "%d/%m/%Y %H:%M"):
                try:
                    return datetime.datetime.strptime(ds + " " + ts, fmt)
                except ValueError:
                    continue
            return None

        dt_from = _bound_dt(flt_from_date.get(), flt_from_time.get(), "00:00")
        dt_to = _bound_dt(flt_to_date.get(), flt_to_time.get(), "23:59")

        for row_data, tag, r_dt, r_flags in cached_results:
            pir_val = row_data[res_col_idx["PIR ISSUE"]]
            risky_val = row_data[res_col_idx["Risky"]]
            exp_txt = str(row_data[res_col_idx["Expiry"]])
            if want == "Risky Only" and not risky_val:
                continue
            elif want == "Expired Only" and "EXPIRED" not in exp_txt.upper():
                continue
            elif want == "Disabled Only" and not r_flags.get("disabled"):
                continue
            elif want == "Blank Description" and not r_flags.get("no_desc"):
                continue
            elif want == "Deny / Drop Only" and not r_flags.get("deny"):
                continue
            elif want == "Added" and r_flags.get("change_type") != "added":
                continue
            elif want == "Edited" and r_flags.get("change_type") != "edited":
                continue
            elif want == "Removed" and r_flags.get("change_type") not in ("removed", "deleted"):
                continue
            elif want not in (
                "All", "Added", "Edited", "Removed", "Risky Only",
                "Expired Only", "Disabled Only", "Blank Description", "Deny / Drop Only"
            ) and pir_val != want:
                continue
            if dt_from is not None and (r_dt is None or r_dt < dt_from):
                continue
            if dt_to is not None and (r_dt is None or r_dt > dt_to):
                continue
            if qtxt:
                if field_name == "All Fields":
                    if not any(qtxt in str(x).lower() for x in row_data):
                        continue
                elif field_name == "Source & Destination":
                    both_sd = (
                        str(row_data[res_col_idx["Source"]])
                        + " "
                        + str(row_data[res_col_idx["Destination"]])
                    ).lower()
                    if qtxt not in both_sd:
                        continue
                else:
                    idx_f = res_col_idx.get(field_name)
                    if idx_f is not None and qtxt not in str(row_data[idx_f]).lower():
                        continue
            filtered_results.append(row_data)
            _iid = res_tree.insert("", "end", values=row_data, tags=(tag,))
            res_iid_uid[_iid] = r_flags.get("uid")
        flt_count_var.set("Showing %d of %d rule(s)" % (len(filtered_results), len(cached_results)))

    def clear_filters():
        flt_status.set("All")
        flt_field.set("All Fields")
        flt_search.set("")
        flt_from_date.set("")
        flt_from_time.set("00:00")
        flt_to_date.set("")
        flt_to_time.set("23:59")
        populate_results()

    ttk.Button(flt_bar, text="Search", style="DXC.TButton", command=lambda: populate_results()).pack(side="left", padx=4)
    ttk.Button(flt_bar, text="Clear", width=7, command=clear_filters).pack(side="left", padx=2)
    flt_search_ent.bind("<Return>", populate_results)
    for w in (from_date_cb, from_time_cb, to_date_cb, to_time_cb):
        w.bind("<Return>", populate_results)

    def jump_to_results(filter_val):
        flt_status.set(filter_val)
        populate_results()
        select_page("results")

    ttk.Button(btn_bar, text="Deviations (YES)", style="Sec.TButton", command=lambda: jump_to_results("YES")).pack(
        side="right", padx=3
    )
    ttk.Button(btn_bar, text="High-Risk Rules", style="Sec.TButton", command=lambda: jump_to_results("Risky Only")).pack(
        side="right", padx=3
    )

    def inspect_rule_popup(event=None):
        sel = res_tree.selection()
        if not sel:
            return
        vals = res_tree.item(sel[0], "values")
        if not vals:
            return
        pop = tk.Toplevel(root)
        pop.title("Rule Inspector — %s" % vals[res_col_idx["Rule Name"]])
        pop.geometry("700x480")
        pop.configure(bg="#F0F4FA")
        tk.Frame(pop, bg="#0B1930", height=44).pack(fill="x")
        tk.Label(
            pop, text="Rule Inspection Detail (%s)" % vals[res_col_idx["Tab"]],
            bg="#0B1930", fg="#FFFFFF", font=("Segoe UI", 10, "bold"),
        ).place(x=14, y=11)
        tk.Frame(pop, bg="#FF6B35", height=3).pack(fill="x")
        box = tk.Text(pop, wrap="word", font=("Consolas", 10), bg="#FFFFFF", fg="#0B1930", padx=14, pady=12)
        box.pack(fill="both", expand=True, padx=12, pady=12)
        for cname, cval in zip(res_cols, vals):
            box.insert("end", "%-14s: %s\n\n" % (cname, cval))
        _c = last_ctx_holder["ctx"]
        _uid = res_iid_uid.get(sel[0])
        _r = next((x for x in _c.rules if x.uid == _uid), None) if _c else None
        if _r is not None:
            _v = _c.verdicts[_r.uid]
            box.insert("end", "%-14s: %s\n%-14s  %s\n\n" % ("Confidence", _v.confidence, "", _v.confidence_why))
            box.insert("end", "WHY (step by step)\n")
            for _st, _res, _d in explain_verdict(_r, _v):
                box.insert("end", "  [%-4s] %-36s %s\n" % (_res, _st, _d))
        box.configure(state="disabled")

    def _ov_path():
        c = last_ctx_holder["ctx"]
        f = ((c.cfg if c else load_config()).get("review") or {}).get("overrides_file") or OVERRIDES_FILE
        return f if os.path.isabs(f) else os.path.join(tool_dir(), f)

    def _ov_user():
        return (logged_in_user["name"] or var["operator"].get() or default_operator() or "").strip()

    def override_rule_ui():
        c = last_ctx_holder["ctx"]
        sel = res_tree.selection()
        if not c or not sel:
            return
        uid = res_iid_uid.get(sel[0])
        rule = next((x for x in c.rules if x.uid == uid), None)
        if rule is None:
            return
        v = c.verdicts[rule.uid]
        user = _ov_user()
        if not user:
            messagebox.showwarning("Operator needed", "Set the Operator User ID first: overrides record who made them.")
            return
        need_appr = (c.cfg.get("review") or {}).get("require_approval", True)
        pop = tk.Toplevel(root)
        pop.title("Override verdict — %s" % rule.name)
        pop.geometry("620x470")
        pop.configure(bg="#F5F7FB")
        pop.transient(root)
        frm = tk.Frame(pop, bg="#F5F7FB", padx=18, pady=14)
        frm.pack(fill="both", expand=True)
        tk.Label(frm, text="Rule %s  (%s, row %s)" % (rule.name, rule.tab, rule.tab_row),
                 bg="#F5F7FB", fg="#0B1930", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        tk.Label(frm, text="Tool verdict: PIR ISSUE = %s   |   Confidence: %s" % (v.tool_status or v.status, v.confidence),
                 bg="#F5F7FB", fg="#334155").pack(anchor="w", pady=(2, 8))
        tk.Label(frm, text=v.detail[:400], wraplength=570, justify="left",
                 bg="#FFFFFF", fg="#334155", padx=8, pady=6).pack(fill="x")
        fst = tk.StringVar(value="NO" if v.status in ("YES", "REVIEW") else "YES")
        frs = tk.StringVar(value=OVERRIDE_REASONS[0])
        fexp = tk.StringVar(value="")
        row1 = tk.Frame(frm, bg="#F5F7FB"); row1.pack(fill="x", pady=(12, 4))
        tk.Label(row1, text="Final PIR ISSUE", bg="#F5F7FB", width=16, anchor="w").pack(side="left")
        ttk.Combobox(row1, textvariable=fst, values=FINAL_STATUSES, state="readonly", width=10).pack(side="left")
        row2 = tk.Frame(frm, bg="#F5F7FB"); row2.pack(fill="x", pady=4)
        tk.Label(row2, text="Reason", bg="#F5F7FB", width=16, anchor="w").pack(side="left")
        ttk.Combobox(row2, textvariable=frs, values=OVERRIDE_REASONS, state="readonly", width=46).pack(side="left")
        tk.Label(frm, text="Comment / evidence (required)", bg="#F5F7FB").pack(anchor="w", pady=(8, 2))
        cbox = tk.Text(frm, height=5, wrap="word", font=("Segoe UI", 9))
        cbox.pack(fill="x")
        row3 = tk.Frame(frm, bg="#F5F7FB"); row3.pack(fill="x", pady=6)
        tk.Label(row3, text="Expires (DD-MM-YYYY, optional)", bg="#F5F7FB").pack(side="left")
        tk.Entry(row3, textvariable=fexp, width=14).pack(side="left", padx=6)
        tk.Label(frm, text=("Saved as PROPOSED. A different user must approve it before it is used (maker-checker)."
                            if need_appr else "Saved as APPROVED (review.require_approval is off)."),
                 bg="#F5F7FB", fg="#B45309", wraplength=570, justify="left").pack(anchor="w", pady=4)

        def save():
            com = cbox.get("1.0", "end").strip()
            if not com:
                messagebox.showwarning("Comment needed", "Write why the tool verdict is wrong (evidence).", parent=pop)
                return
            try:
                path = _ov_path()
                data = load_overrides(path)
                data["overrides"].append(new_override(
                    rule, fst.get(), frs.get(), com, user,
                    "proposed" if need_appr else "approved", fexp.get()))
                save_overrides(data, path)
            except (AuditError, OSError) as e:
                messagebox.showerror("Override not saved", str(e), parent=pop)
                return
            pop.destroy()
            messagebox.showinfo("Override saved", "Saved to %s.\nRun the audit again to produce the final report with this override." % path)

        bt = tk.Frame(frm, bg="#F5F7FB"); bt.pack(fill="x", pady=(10, 0))
        tk.Button(bt, text="Save override", command=save, bg="#1D4ED8", fg="#FFFFFF", relief="flat", padx=14, pady=4).pack(side="right")
        tk.Button(bt, text="Cancel", command=pop.destroy, relief="flat", padx=14, pady=4).pack(side="right", padx=8)

    def review_overrides_ui():
        path = _ov_path()
        try:
            data = load_overrides(path)
        except AuditError as e:
            messagebox.showerror("Overrides", str(e))
            return
        user = _ov_user()
        pop = tk.Toplevel(root)
        pop.title("Reviewer overrides — %s" % path)
        pop.geometry("980x420")
        cols = ("State", "Tab", "Rule", "Final", "Reason", "Comment", "By", "At", "Approved by")
        tv = ttk.Treeview(pop, columns=cols, show="headings")
        for cn, w in zip(cols, (80, 80, 150, 60, 170, 220, 80, 120, 90)):
            tv.heading(cn, text=cn); tv.column(cn, width=w, anchor="w")
        tv.pack(fill="both", expand=True, padx=10, pady=10)

        def fill():
            for it in tv.get_children():
                tv.delete(it)
            for ov in data["overrides"]:
                tv.insert("", "end", iid=ov["id"], values=(
                    ov.get("state"), ov.get("tab"), ov.get("rule"), ov.get("final_status"),
                    ov.get("reason"), ov.get("comment"), ov.get("by"), ov.get("at"), ov.get("approved_by")))

        def act(new_state):
            sel = tv.selection()
            if not sel:
                return
            ov = next(o for o in data["overrides"] if o["id"] == sel[0])
            if new_state == "approved":
                if ov.get("state") != "proposed":
                    messagebox.showwarning("Approve", "Only PROPOSED overrides can be approved.", parent=pop)
                    return
                if not user or user.lower() == (ov.get("by") or "").lower():
                    messagebox.showwarning("Maker-checker", "The person who proposed an override cannot approve it.", parent=pop)
                    return
                ov["approved_by"] = user
                ov["approved_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            else:
                ov["closed_by"] = user
            ov["state"] = new_state
            save_overrides(data, path)
            fill()

        bt = tk.Frame(pop); bt.pack(fill="x", padx=10, pady=(0, 10))
        tk.Label(bt, text="Signed in as: %s" % (user or "(not set)")).pack(side="left")
        tk.Button(bt, text="Revoke", command=lambda: act("revoked")).pack(side="right", padx=4)
        tk.Button(bt, text="Reject", command=lambda: act("rejected")).pack(side="right", padx=4)
        tk.Button(bt, text="Approve", command=lambda: act("approved")).pack(side="right", padx=4)
        fill()

    ctx_menu = tk.Menu(root, tearoff=0)

    def _copy_sel(mode):
        sel = res_tree.selection()
        if not sel:
            return
        vals = res_tree.item(sel[0], "values")
        if not vals:
            return
        if mode == "rfc":
            txt = str(vals[res_col_idx["RFC Match"]])
        elif mode == "flow":
            txt = "%s -> %s (%s)" % (
                vals[res_col_idx["Source"]], vals[res_col_idx["Destination"]], vals[res_col_idx["Service"]],
            )
        else:
            txt = "\n".join("%s: %s" % (c, v) for c, v in zip(res_cols, vals) if str(v).strip())
        root.clipboard_clear()
        root.clipboard_append(txt)

    ctx_menu.add_command(label="Inspect Rule Detail", command=inspect_rule_popup)
    ctx_menu.add_command(label="Override Verdict (False Positive)...", command=lambda: override_rule_ui())
    ctx_menu.add_command(label="Review / Approve Overrides...", command=lambda: review_overrides_ui())
    ctx_menu.add_separator()
    ctx_menu.add_command(label="Copy Rule Summary", command=lambda: _copy_sel("summary"))
    ctx_menu.add_command(label="Copy RFC Number", command=lambda: _copy_sel("rfc"))
    ctx_menu.add_command(label="Copy Source / Dest / Service", command=lambda: _copy_sel("flow"))

    def show_ctx_menu(event):
        iid = res_tree.identify_row(event.y)
        if iid:
            res_tree.selection_set(iid)
            ctx_menu.tk_popup(event.x_root, event.y_root)

    res_tree.bind("<Double-1>", inspect_rule_popup)
    res_tree.bind("<Button-3>", show_ctx_menu)
    res_tree.bind("<Button-2>", show_ctx_menu)

    def export_filtered_csv():
        if not filtered_results:
            messagebox.showwarning("No Data", "No filtered rules to export.")
            return
        out_p = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV File", "*.csv")], initialfile="Filtered_Audit_Results.csv"
        )
        if not out_p:
            return
        with open(out_p, "w", encoding="utf-8-sig", newline="") as f:
            w = csv.writer(f)
            w.writerow(res_cols)
            for row_data in filtered_results:
                w.writerow([csv_safe(v) for v in row_data])
        messagebox.showinfo("Exported", "Saved %d row(s) to:\n%s" % (len(filtered_results), out_p))

    def export_filtered_xlsx(exceptions_only=False):
        rows_to_exp = (
            [r for r, _, _, _ in cached_results if r[res_col_idx["PIR ISSUE"]] in ("YES", "REVIEW") or bool(r[res_col_idx["Risky"]])]
            if exceptions_only
            else list(filtered_results)
        )
        if not rows_to_exp:
            messagebox.showwarning("No Data", "No matching rules to export.")
            return
        out_p = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel Workbook", "*.xlsx")],
            initialfile="Audit_Exceptions.xlsx" if exceptions_only else "Filtered_Audit_Results.xlsx",
        )
        if not out_p:
            return
        bk = Book()
        ws = bk.sheet("Exceptions" if exceptions_only else "Filtered Results")
        title_block(
            ws,
            "DXC Technology — %s" % ("Audit Exceptions Report" if exceptions_only else "Filtered Audit Results"),
            ["Exported %s | %d rule(s)" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), len(rows_to_exp))],
        )
        table(
            ws, 4, list(res_cols), rows_to_exp, [12, 24, 18, 18, 28, 28, 22, 12, 12, 14, 26, 48],
            status_cols=(res_col_idx["PIR ISSUE"] + 1,), center_cols=(res_col_idx["PIR ISSUE"] + 1,),
        )
        ws.fit = True
        bk.save(out_p)
        messagebox.showinfo("Exported", "Saved %d row(s) to:\n%s" % (len(rows_to_exp), out_p))

    ttk.Button(dt_bar, text="Exceptions (.xlsx)", command=lambda: export_filtered_xlsx(True)).pack(side="right", padx=2)
    ttk.Button(dt_bar, text="Excel (.xlsx)", command=lambda: export_filtered_xlsx(False)).pack(side="right", padx=2)
    ttk.Button(dt_bar, text="CSV", command=export_filtered_csv).pack(side="right", padx=2)
    tk.Label(dt_bar, text="Export:", bg="#FFFFFF", font=("Segoe UI", 8, "bold")).pack(side="right", padx=(4, 2))

    # =========================================================================
    # PAGE 2B: COMPLIANCE (ISO/IEC 27001:2022, PCI DSS v4.0.1, NIST 800-53)
    # =========================================================================
    p_comp = pages["comp"]
    c_top_card, c_top_in = make_card(p_comp, title=None, compact=True)
    c_top_card.pack(fill="x", pady=(0, 6))

    tk.Label(c_top_in, text="Framework:", bg="#FFFFFF", font=("Segoe UI", 9, "bold")).pack(side="left")
    v_comp_fw = tk.StringVar(value=load_config().get("compliance_framework", "all"))
    comp_fw_cb = ttk.Combobox(
        c_top_in, textvariable=v_comp_fw, values=["all", "iso", "pci", "nist", "off"], state="readonly", width=10
    )
    comp_fw_cb.pack(side="left", padx=(4, 10))
    tk.Label(
        c_top_in,
        text="Click any control row below to drill into impacted rules  •  Right-click rules to copy or inspect",
        bg="#FFFFFF",
        fg="#475569",
        font=("Segoe UI", 8, "bold"),
    ).pack(side="left")

    def export_comp_xlsx_ui():
        c = last_ctx_holder["ctx"]
        if c is None:
            messagebox.showwarning("No Audit", "Run an audit first to export the Compliance Report.")
            return
        out_p = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel Workbook", "*.xlsx")],
            initialfile="Compliance_Audit_Report_%s.xlsx" % c.report_date.strftime("%d-%m-%Y"),
        )
        if not out_p:
            return
        export_compliance_xlsx(c, out_p, v_comp_fw.get())
        _open_path(out_p)
        messagebox.showinfo("Exported", "Compliance report saved to:\n%s" % out_p)

    def export_comp_html_ui():
        c = last_ctx_holder["ctx"]
        if c is None:
            messagebox.showwarning("No Audit", "Run an audit first.")
            return
        out_p = filedialog.asksaveasfilename(
            defaultextension=".html", filetypes=[("HTML Report", "*.html")],
            initialfile="Compliance_Executive_Brief_%s.html" % c.report_date.strftime("%d-%m-%Y"),
        )
        if out_p:
            export_compliance_html(c, out_p, v_comp_fw.get())
            _open_path(out_p)
            messagebox.showinfo("Exported", "Compliance HTML brief saved to:\n%s" % out_p)

    def export_comp_csv_ui():
        if not comp_cache["shown_rows"]:
            messagebox.showwarning("No Rules", "No impacted rules to export.")
            return
        out_p = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("CSV File", "*.csv")],
            initialfile="Compliance_Impacted_Rules.csv",
        )
        if out_p:
            with open(out_p, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f)
                w.writerow(cr_cols)
                for row_v in comp_cache["shown_rows"]:
                    w.writerow([csv_safe(v) for v in row_v])
            messagebox.showinfo("Exported", "Saved %d rule(s) to:\n%s" % (len(comp_cache["shown_rows"]), out_p))

    def export_comp_json_ui():
        c = last_ctx_holder["ctx"]
        if c is None:
            messagebox.showwarning("No Audit", "Run an audit first.")
            return
        out_p = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("JSON Evidence", "*.json")],
            initialfile="Compliance_Evidence_%s.json" % c.report_date.strftime("%d-%m-%Y"),
        )
        if out_p:
            export_compliance_json(c, out_p, v_comp_fw.get())
            messagebox.showinfo("Exported", "Compliance JSON evidence saved to:\n%s" % out_p)

    def copy_remediation_plan():
        c = last_ctx_holder["ctx"]
        if c is None:
            return
        sc_rows, _ = compliance_evaluate(c, v_comp_fw.get())
        lines = ["DXC Firewall Compliance Remediation Plan (%s):" % c.report_date.strftime("%d-%b-%Y")]
        for r in sc_rows:
            if r[5] != "PASS":
                lines.append("- [%s] %s %s (%s): %d rule(s) -> %s" % (r[5], r[0], r[1], r[2], r[4], r[6]))
        txt = "\n".join(lines)
        root.clipboard_clear()
        root.clipboard_append(txt)
        messagebox.showinfo("Copied", "Copied remediation summary (%d line(s)) to clipboard." % (len(lines) - 1))

    ttk.Button(c_top_in, text="JSON", command=export_comp_json_ui).pack(side="right", padx=2)
    ttk.Button(c_top_in, text="CSV", command=export_comp_csv_ui).pack(side="right", padx=2)
    ttk.Button(c_top_in, text="HTML Brief", command=export_comp_html_ui).pack(side="right", padx=2)
    ttk.Button(c_top_in, text="Excel (.xlsx)", style="DXC.TButton", command=export_comp_xlsx_ui).pack(side="right", padx=2)
    ttk.Button(c_top_in, text="Copy Remediation Plan", command=copy_remediation_plan).pack(side="right", padx=(2, 8))

    c_kpi_strip = tk.Frame(p_comp, bg="#F0F4FA")
    c_kpi_strip.pack(fill="x", pady=(0, 6))
    c_kpi_vars = {}
    for idx, (ck, ct, ca, cb) in enumerate([
        ("total", "CONTROLS EVALUATED", "#2563EB", "#EFF6FF"),
        ("pass", "PASSING CONTROLS", "#16A34A", "#F0FDF4"),
        ("fail", "FAILED CONTROLS", "#DC2626", "#FEF2F2"),
        ("score", "CONTROL SCORE", "#FF6B35", "#FFF7ED"),
    ]):
        c_kpi_strip.columnconfigure(idx, weight=1)
        cc = tk.Frame(c_kpi_strip, bg="#FFFFFF", highlightbackground="#D5E2F4", highlightthickness=1)
        cc.grid(row=0, column=idx, sticky="ew", padx=(0 if idx == 0 else 5, 0 if idx == 3 else 5))
        tk.Frame(cc, bg=ca, height=3).pack(fill="x")
        cb_f = tk.Frame(cc, bg=cb, padx=10, pady=5)
        cb_f.pack(fill="both", expand=True)
        c_kpi_vars[ck] = tk.StringVar(value="—")
        tk.Label(cb_f, text=ct, bg=cb, fg="#475569", font=("Segoe UI", 8, "bold")).pack(anchor="w")
        tk.Label(cb_f, textvariable=c_kpi_vars[ck], bg=cb, fg=ca, font=("Segoe UI", 16, "bold")).pack(anchor="w")

    # Top Scorecard Card (compact height=6)
    c_tbl_card, c_tbl_in = make_card(p_comp, "Compliance Control Scorecard (Click a Control to Drill Down)", compact=True)
    c_tbl_card.pack(fill="x", pady=(0, 6))
    c_cols = ("Framework", "Control ID", "Control Area", "Trigger Condition", "Impacted Rules", "Status", "Guidance")
    c_tree = ttk.Treeview(c_tbl_in, columns=c_cols, show="headings", height=6)
    for col, w in zip(c_cols, (145, 115, 165, 195, 95, 75, 290)):
        c_tree.column(col, width=w, anchor="center" if col in ("Impacted Rules", "Status") else "w")
    make_sortable(c_tree, c_cols)
    c_tree.tag_configure("PASS", background="#DCFCE7")
    c_tree.tag_configure("FAIL", background="#FEE2E2")
    c_tree.tag_configure("REVIEW", background="#FEF3C7")
    cs_y = ttk.Scrollbar(c_tbl_in, orient="vertical", command=c_tree.yview)
    c_tree.configure(yscrollcommand=cs_y.set)
    cs_y.pack(side="right", fill="y")
    c_tree.pack(side="left", fill="both", expand=True)

    # Bottom Interactive Impacted Rules Card
    cr_card, cr_in = make_card(p_comp, title=None, compact=True)
    cr_card.pack(fill="both", expand=True)
    cr_bar = tk.Frame(cr_in, bg="#FFFFFF")
    cr_bar.pack(fill="x", pady=(0, 4))
    cr_hdr_var = tk.StringVar(value="Impacted Rules: Select a control above or click \"Show All Impacted\"")
    tk.Label(cr_bar, textvariable=cr_hdr_var, bg="#FFFFFF", fg="#1E3A8A", font=("Segoe UI", 9, "bold")).pack(side="left")

    cr_cols = (
        "Tab", "Rule Name", "RFC Match", "Source", "Destination",
        "Service", "PIR ISSUE", "Risky", "Expiry", "Asset Owner", "Control Ref", "Recommended Action",
    )
    cr_idx = dict((c, i) for i, c in enumerate(cr_cols))
    cr_wrap = tk.Frame(cr_in, bg="#FFFFFF")
    cr_wrap.pack(fill="both", expand=True)
    c_rule_tree = ttk.Treeview(cr_wrap, columns=cr_cols, show="headings")
    cr_widths = {
        "Tab": 80, "Rule Name": 145, "RFC Match": 95, "Source": 145, "Destination": 145,
        "Service": 115, "PIR ISSUE": 75, "Risky": 75, "Expiry": 95, "Asset Owner": 130,
        "Control Ref": 165, "Recommended Action": 240,
    }
    for col in cr_cols:
        c_rule_tree.column(col, width=cr_widths[col], anchor="w")
    make_sortable(c_rule_tree, cr_cols)
    c_rule_tree.tag_configure("YES", background="#FEE2E2")
    c_rule_tree.tag_configure("NO", background="#DCFCE7")
    c_rule_tree.tag_configure("REVIEW", background="#FEF3C7")
    c_rule_tree.tag_configure("N/A", background="#F1F5F9")
    crs_y = ttk.Scrollbar(cr_wrap, orient="vertical", command=c_rule_tree.yview)
    crs_x = ttk.Scrollbar(cr_wrap, orient="horizontal", command=c_rule_tree.xview)
    c_rule_tree.configure(yscrollcommand=crs_y.set, xscrollcommand=crs_x.set)
    crs_y.pack(side="right", fill="y")
    crs_x.pack(side="bottom", fill="x")
    c_rule_tree.pack(side="left", fill="both", expand=True)

    comp_cache = {"hits": {}, "refs": {}, "actions": {}, "shown_rows": []}

    comp_active_pair = {"pair": None}
    comp_search_var = tk.StringVar(value="")

    def _populate_comp_rules(filter_pair="KEEP"):
        if filter_pair != "KEEP":
            comp_active_pair["pair"] = filter_pair
        fp = comp_active_pair["pair"]
        for item in c_rule_tree.get_children():
            c_rule_tree.delete(item)
        comp_cache["shown_rows"].clear()
        c = last_ctx_holder["ctx"]
        if c is None:
            return
        if fp is not None:
            rules_src = comp_cache["hits"].get(fp, [])
            base_lbl = "Impacted Rules — %s %s" % (fp[0], fp[1])
        else:
            rules_src = [r for r in c.rules if comp_cache["refs"].get(r.uid)]
            base_lbl = "All Impacted Rules"
        q_comp = comp_search_var.get().strip().lower()
        shown_cnt = 0
        for r in rules_src:
            v = c.verdicts[r.uid]
            rec = smax_record(c.smax, r, c.cfg)
            exp_val = (rec.get("expiry") or "Permanent") if rec is not None else ""
            exp_st = expiry_status(exp_val, c.report_date)
            if isinstance(exp_val, (datetime.date, datetime.datetime)):
                exp_val = exp_val.strftime("%d-%b-%Y")
            if exp_st in ("EXPIRED",) or exp_st.startswith("EXPIRING SOON"):
                exp_val = "%s [%s]" % (exp_val, exp_st)
            row_v = (
                r.tab, r.name, ", ".join("RFC" + n for n in r.chain),
                r.src.summary(3) if r.src else "", r.dst.summary(3) if r.dst else "",
                r.ports.fmt() or ", ".join(r.svc_tokens), v.status, ", ".join(v.risky_ports),
                str(exp_val), c.owners[r.uid][0], comp_cache["refs"].get(r.uid, ""),
                comp_cache["actions"].get(r.uid, ""),
            )
            if q_comp and not any(q_comp in str(x).lower() for x in row_v):
                continue
            shown_cnt += 1
            comp_cache["shown_rows"].append(row_v)
            c_rule_tree.insert("", "end", values=row_v, tags=(v.status,))
        cr_hdr_var.set("%s (%d rule(s))" % (base_lbl, shown_cnt))

    def on_comp_control_select(event=None):
        sel = c_tree.selection()
        if not sel:
            return
        vals = c_tree.item(sel[0], "values")
        if vals:
            _populate_comp_rules((vals[0], vals[1]))

    c_tree.bind("<<TreeviewSelect>>", on_comp_control_select)

    def export_selected_ctrl_xlsx():
        if not comp_cache["shown_rows"]:
            messagebox.showwarning("No Rules", "No impacted rules currently displayed.")
            return
        out_p = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel Workbook", "*.xlsx")],
            initialfile="Compliance_Impacted_Rules.xlsx",
        )
        if not out_p:
            return
        bk = Book()
        ws = bk.sheet("Impacted Rules")
        title_block(ws, "DXC Technology — Compliance Impacted Rules", [cr_hdr_var.get()])
        table(
            ws, 4, list(cr_cols), [list(x) for x in comp_cache["shown_rows"]],
            [12, 22, 16, 26, 26, 20, 12, 14, 14, 22, 28, 38],
            status_cols=(cr_idx["PIR ISSUE"] + 1,), center_cols=(cr_idx["PIR ISSUE"] + 1,),
        )
        ws.fit = True
        bk.save(out_p)
        messagebox.showinfo("Exported", "Saved %d rule(s) to:\n%s" % (len(comp_cache["shown_rows"]), out_p))

    ttk.Button(cr_bar, text="Export View (.xlsx)", command=export_selected_ctrl_xlsx).pack(side="right", padx=2)
    ttk.Button(cr_bar, text="Show All Impacted", style="Sec.TButton", command=lambda: _populate_comp_rules(None)).pack(
        side="right", padx=4
    )
    comp_search_ent = ttk.Entry(cr_bar, textvariable=comp_search_var, width=20)
    comp_search_ent.pack(side="right", padx=(2, 6))
    tk.Label(cr_bar, text="Filter:", bg="#FFFFFF", font=("Segoe UI", 8, "bold")).pack(side="right")
    comp_search_var.trace_add("write", lambda *_: _populate_comp_rules("KEEP"))

    def inspect_comp_rule(event=None):
        sel = c_rule_tree.selection()
        if not sel:
            return
        vals = c_rule_tree.item(sel[0], "values")
        if not vals:
            return
        pop = tk.Toplevel(root)
        pop.title("Compliance Rule Inspector — %s" % vals[cr_idx["Rule Name"]])
        pop.geometry("700x480")
        pop.configure(bg="#F0F4FA")
        tk.Frame(pop, bg="#0B1930", height=44).pack(fill="x")
        tk.Label(
            pop, text="Compliance Finding (%s)" % vals[cr_idx["Tab"]],
            bg="#0B1930", fg="#FFFFFF", font=("Segoe UI", 10, "bold"),
        ).place(x=14, y=11)
        tk.Frame(pop, bg="#FF6B35", height=3).pack(fill="x")
        box = tk.Text(pop, wrap="word", font=("Consolas", 10), bg="#FFFFFF", fg="#0B1930", padx=14, pady=12)
        box.pack(fill="both", expand=True, padx=12, pady=12)
        for cname, cval in zip(cr_cols, vals):
            box.insert("end", "%-18s: %s\n\n" % (cname, cval))
        box.configure(state="disabled")

    cr_menu = tk.Menu(root, tearoff=0)

    def _copy_comp_sel(mode):
        sel = c_rule_tree.selection()
        if not sel:
            return
        vals = c_rule_tree.item(sel[0], "values")
        if not vals:
            return
        if mode == "name":
            txt = str(vals[cr_idx["Rule Name"]])
        elif mode == "rfc":
            txt = str(vals[cr_idx["RFC Match"]])
        elif mode == "src":
            txt = str(vals[cr_idx["Source"]])
        elif mode == "dst":
            txt = str(vals[cr_idx["Destination"]])
        elif mode == "svc":
            txt = str(vals[cr_idx["Service"]])
        elif mode == "flow":
            txt = "%s -> %s (%s)" % (vals[cr_idx["Source"]], vals[cr_idx["Destination"]], vals[cr_idx["Service"]])
        elif mode == "jump":
            flt_status.set("All")
            flt_field.set("Rule Name")
            flt_search.set(str(vals[cr_idx["Rule Name"]]))
            populate_results()
            select_page("results")
            return
        else:
            txt = "\n".join("%s: %s" % (c, v) for c, v in zip(cr_cols, vals) if str(v).strip())
        root.clipboard_clear()
        root.clipboard_append(txt)

    cr_menu.add_command(label="Inspect Rule & Action", command=inspect_comp_rule)
    cr_menu.add_command(label="Open in Audit Results", command=lambda: _copy_comp_sel("jump"))
    cr_menu.add_separator()
    cr_menu.add_command(label="Copy Rule Name", command=lambda: _copy_comp_sel("name"))
    cr_menu.add_command(label="Copy RFC Number", command=lambda: _copy_comp_sel("rfc"))
    cr_menu.add_command(label="Copy Source", command=lambda: _copy_comp_sel("src"))
    cr_menu.add_command(label="Copy Destination", command=lambda: _copy_comp_sel("dst"))
    cr_menu.add_command(label="Copy Service", command=lambda: _copy_comp_sel("svc"))
    cr_menu.add_command(label="Copy Source -> Dest (Service)", command=lambda: _copy_comp_sel("flow"))
    cr_menu.add_separator()
    cr_menu.add_command(label="Copy Full Compliance Finding", command=lambda: _copy_comp_sel("full"))

    def show_cr_menu(event):
        iid = c_rule_tree.identify_row(event.y)
        if iid:
            c_rule_tree.selection_set(iid)
            cr_menu.tk_popup(event.x_root, event.y_root)

    c_rule_tree.bind("<Double-1>", inspect_comp_rule)
    c_rule_tree.bind("<Button-3>", show_cr_menu)
    c_rule_tree.bind("<Button-2>", show_cr_menu)

    def refresh_compliance(*_):
        for item in c_tree.get_children():
            c_tree.delete(item)
        c = last_ctx_holder["ctx"]
        if c is None:
            return
        sc_rows, rule_refs = compliance_evaluate(c, v_comp_fw.get())
        hits_map, act_map = compliance_hits_map(c, v_comp_fw.get())
        comp_cache["hits"] = hits_map
        comp_cache["refs"] = rule_refs
        comp_cache["actions"] = act_map
        for row in sc_rows:
            c_tree.insert("", "end", values=row, tags=(row[5],))
        tot_c = len(sc_rows)
        pass_c = sum(1 for r in sc_rows if r[5] == "PASS")
        fail_c = sum(1 for r in sc_rows if r[5] == "FAIL")
        c_kpi_vars["total"].set(str(tot_c))
        c_kpi_vars["pass"].set(str(pass_c))
        c_kpi_vars["fail"].set(str(fail_c))
        c_kpi_vars["score"].set(("%d%%" % int(round(100.0 * pass_c / tot_c))) if tot_c else "—")
        _populate_comp_rules(None)

    comp_fw_cb.bind("<<ComboboxSelected>>", refresh_compliance)

    # =========================================================================
    # PAGE 3: MASTER CONSOLIDATOR
    # =========================================================================
    p_mas = pages["master"]
    m_card, m_in = make_card(p_mas, "Multi-Day Master Consolidation (30 / 60 / 90 Days)")
    m_card.pack(fill="x", pady=(0, 10))
    m_in.columnconfigure(1, weight=1)
    v_min = tk.StringVar(value=state.get("master_in", ""))
    v_mout = tk.StringVar(value=state.get("master_out", os.path.join(tool_dir(), "master_output")))
    v_mfmt = tk.StringVar(value="both")
    v_mbadge = tk.StringVar(value="○ Select folder")

    def refresh_mbadge(*_):
        p_in = v_min.get().strip()
        if p_in and os.path.isdir(p_in):
            cnt = sum(
                1 for fn in os.listdir(p_in)
                if fn.lower().endswith((".xlsx", ".xlsm")) and not fn.startswith("~$") and not fn.startswith("Master_")
            )
            v_mbadge.set("● %d workbook(s) ready" % cnt)
        elif p_in:
            v_mbadge.set("✕ Folder not found")
        else:
            v_mbadge.set("○ Select folder")

    v_min.trace_add("write", refresh_mbadge)

    def pick_mdir(tv):
        d = filedialog.askdirectory(initialdir=tv.get() or tool_dir())
        if d:
            tv.set(d)

    tk.Label(m_in, text="Daily Consolidated Folder", bg="#FFFFFF").grid(row=0, column=0, sticky="w", pady=4)
    ttk.Entry(m_in, textvariable=v_min).grid(row=0, column=1, sticky="ew", padx=8, pady=4)
    ttk.Button(m_in, text="Browse", width=9, command=lambda: pick_mdir(v_min)).grid(row=0, column=2, padx=4)
    tk.Label(m_in, textvariable=v_mbadge, width=22, bg="#FFFFFF", fg="#2563EB", font=("Segoe UI", 8, "bold")).grid(row=0, column=3, sticky="w", padx=6)

    tk.Label(m_in, text="Master Output Folder", bg="#FFFFFF").grid(row=1, column=0, sticky="w", pady=4)
    ttk.Entry(m_in, textvariable=v_mout).grid(row=1, column=1, sticky="ew", padx=8, pady=4)
    ttk.Button(m_in, text="Browse", width=9, command=lambda: pick_mdir(v_mout)).grid(row=1, column=2, padx=4)

    tk.Label(m_in, text="Export Format", bg="#FFFFFF", font=("Segoe UI", 9, "bold")).grid(row=2, column=0, sticky="w", pady=6)
    fmt_box = tk.Frame(m_in, bg="#FFFFFF")
    fmt_box.grid(row=2, column=1, columnspan=3, sticky="w", padx=8, pady=6)
    ttk.Radiobutton(fmt_box, text="Both Formats (Multi-Tab .xlsx + Flat .xlsx/.csv)", variable=v_mfmt, value="both").pack(side="left", padx=(0, 14))
    ttk.Radiobutton(fmt_box, text="Format 1: Multi-Tab Master (.xlsx)", variable=v_mfmt, value="multitab").pack(side="left", padx=(0, 14))
    ttk.Radiobutton(fmt_box, text="Format 2: Single-Sheet Flat (.xlsx + .csv)", variable=v_mfmt, value="flat").pack(side="left")

    m_log_card, m_log_in = make_card(p_mas, "Consolidation Log")
    m_log_card.pack(fill="both", expand=True)
    m_log = tk.Text(
        m_log_in, height=14, wrap="word", state="disabled", font=("Consolas", 9),
        bg="#0B1930", fg="#E2E8F0", relief="flat", padx=8, pady=6
    )

    def run_master_merge():
        in_d, out_d = v_min.get().strip(), v_mout.get().strip()
        if not in_d or not out_d:
            messagebox.showwarning("Missing Folder", "Select both input and output folders.")
            return
        m_log.configure(state="normal")
        m_log.delete("1.0", "end")
        m_log.insert("end", "Merging consolidated sheets from: %s\n" % in_d)
        m_log.configure(state="disabled")
        try:
            stats, outs = merge_consolidated_folder(in_d, out_d, fmt=v_mfmt.get())
            cached_results.clear()
            for rec in stats["records"]:
                ct_str = clean(rec.get("change time", "")).strip()
                r_dt = parse_time(rec.get("change time"))
                pir_v = clean(rec.get("pir issue", "")).strip() or "REVIEW"
                rsk_v = clean(rec.get("risky ports", "")).strip()
                cached_results.append(
                    (
                        (
                            clean(rec.get("firewall tab", "")),
                            clean(rec.get("name", "")),
                            clean(rec.get("rfc sheet used", "")),
                            r_dt.strftime("%Y-%m-%d %H:%M") if r_dt else ct_str,
                            clean(rec.get("source", ""))[:80],
                            clean(rec.get("destination", ""))[:80],
                            clean(rec.get("service", "") or rec.get("services & applications", ""))[:60],
                            pir_v,
                            rsk_v,
                            clean(rec.get("expiry", "")),
                            clean(rec.get("asset owner", "")),
                            clean(rec.get("pir detail", "")),
                        ),
                        pir_v,
                        r_dt,
                        {
                            "disabled": "disabled" in clean(rec.get("enable", "") or rec.get("status", "")).lower(),
                            "no_desc": not clean(rec.get("description", "") or rec.get("comments", "")).strip(),
                            "deny": any(clean(rec.get("action", "")).strip().lower().startswith(w) for w in DENY_WORDS),
                            "change_type": clean(rec.get("change type", "")).strip().lower(),
                        },
                    )
                )
            avail_dates = sorted(set(x[2].strftime("%Y-%m-%d") for x in cached_results if x[2] is not None))
            from_date_cb.configure(values=avail_dates)
            to_date_cb.configure(values=avail_dates)
            populate_results()
            m_log.configure(state="normal")
            m_log.insert(
                "end",
                "Merged %d file(s), %d tab(s), %d total rules.\nLoaded all %d rules into Audit Results.\n\nOutputs:\n%s\n"
                % (stats["files_read"], stats["tabs"], stats["total_rules"], stats["total_rules"], "\n".join(outs)),
            )
            m_log.configure(state="disabled")
            messagebox.showinfo(
                "Master Consolidation Complete",
                "Merged %d file(s) (%d total rules) and loaded into Audit Results.\n\n%s"
                % (stats["files_read"], stats["total_rules"], "\n".join(outs)),
            )
        except AuditError as e:
            messagebox.showerror("Consolidation Error", str(e))

    m_btns = tk.Frame(m_in, bg="#FFFFFF")
    m_btns.grid(row=3, column=0, columnspan=4, sticky="w", pady=(8, 2))
    ttk.Button(m_btns, text="▶  Consolidate & Load into Audit Results", style="DXC.TButton", command=run_master_merge).pack(
        side="left", padx=(0, 8)
    )
    ttk.Button(m_btns, text="Open Master Output Folder", command=lambda: _open_path(v_mout.get().strip())).pack(side="left")
    m_log.pack(fill="both", expand=True)
    refresh_mbadge()

    # =========================================================================
    # PAGE 4: JOB LOG
    # =========================================================================
    p_jobs = pages["jobs"]
    j_card, j_in = make_card(p_jobs, "Audit Execution History")
    j_card.pack(fill="both", expand=True)
    job_bar = tk.Frame(j_in, bg="#FFFFFF")
    job_bar.pack(fill="x", pady=(0, 8))
    job_cols = ("Timestamp", "Operator", "Report Date", "AlgoSec", "RFCs", "Rules", "PIR YES", "Status")
    job_tree = ttk.Treeview(j_in, columns=job_cols, show="headings")
    for c, w in zip(job_cols, (150, 120, 95, 70, 65, 65, 70, 150)):
        job_tree.column(c, width=w, anchor="center" if w < 110 else "w")
    make_sortable(job_tree, job_cols)
    job_tree.tag_configure("ATTENTION REQUIRED", background="#FEE2E2")
    job_tree.tag_configure("PASS", background="#DCFCE7")
    job_tree.tag_configure("INCOMPLETE", background="#FEF3C7")

    def refresh_jobs():
        for item in job_tree.get_children():
            job_tree.delete(item)
        for j in load_job_log():
            st_val = j.get("status", "")
            job_tree.insert(
                "", "end",
                values=(
                    j.get("timestamp", ""), j.get("operator", ""), j.get("report_date", ""),
                    j.get("algosec_files", 0), j.get("rfc_sheets", 0), j.get("rules", 0),
                    j.get("pir_yes", 0), st_val,
                ),
                tags=(st_val,),
            )

    ttk.Button(job_bar, text="Refresh Job Log", style="Sec.TButton", command=refresh_jobs).pack(side="left")
    tk.Label(
        job_bar, text="  Every audit run is recorded here and included on the Excel Executive Dashboard.",
        bg="#FFFFFF", fg="#475569",
    ).pack(side="left")
    js_y = ttk.Scrollbar(j_in, orient="vertical", command=job_tree.yview)
    job_tree.configure(yscrollcommand=js_y.set)
    job_tree.pack(side="left", fill="both", expand=True)
    js_y.pack(side="right", fill="y")

    # =========================================================================
    # PAGE 5: SETTINGS & SECURITY
    # =========================================================================
    p_cfg = pages["cfg"]
    cfg_cur = load_config()
    top_cfg_row = tk.Frame(p_cfg, bg="#F0F4FA")
    top_cfg_row.pack(fill="x", pady=(0, 10))
    top_cfg_row.columnconfigure(0, weight=1)
    top_cfg_row.columnconfigure(1, weight=1)

    pol_card, pol_in = make_card(top_cfg_row, "Audit Policy & Firewall Routing")
    pol_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
    pol_in.columnconfigure(1, weight=1)

    v_risky = tk.StringVar(value=", ".join(str(x) for x in cfg_cur["risky_ports"]))
    v_merged = tk.StringVar(value=cfg_cur["policy"]["merged_rule"])
    v_multi_rfc = tk.StringVar(value=cfg_cur["policy"].get("multi_rfc", "last"))
    v_combined = tk.StringVar(value=cfg_cur["policy"].get("combined_row_grouping", "enabled"))
    v_deny = tk.StringVar(value=cfg_cur["policy"]["deny_rules"])
    v_removed = tk.StringVar(value=cfg_cur["policy"].get("removed_rules", "skip"))
    v_edited = tk.StringVar(value=cfg_cur["policy"]["edited_scope"])
    v_owner_show = tk.StringVar(value=cfg_cur["asset_owner"]["show"])

    tk.Label(pol_in, text="Risky Ports:", bg="#FFFFFF").grid(row=0, column=0, sticky="w", pady=3)
    ttk.Entry(pol_in, textvariable=v_risky).grid(row=0, column=1, sticky="ew", padx=6, pady=3)
    for ri, (lbl, vv, opts) in enumerate(
        [
            ("Merged-rule policy:", v_merged, ["note", "yes"]),
            ("Multi-RFC policy:", v_multi_rfc, ["last", "union", "first"]),
            ("Combined-row grouping:", v_combined, ["enabled", "strict"]),
            ("Deny/drop rules:", v_deny, ["check", "skip"]),
            ("Removed rules:", v_removed, ["skip", "check"]),
            ("Edited rule scope:", v_edited, ["full", "added"]),
            ("Asset Owner display:", v_owner_show, ["both", "source", "destination"]),
        ],
        1,
    ):
        tk.Label(pol_in, text=lbl, bg="#FFFFFF").grid(row=ri, column=0, sticky="w", pady=3)
        ttk.Combobox(pol_in, textvariable=vv, values=opts, state="readonly", width=18).grid(row=ri, column=1, sticky="w", padx=6, pady=3)

    tk.Label(pol_in, text="Tab Patterns:", bg="#FFFFFF").grid(row=8, column=0, sticky="w", pady=3)
    tab_pat_row = tk.Frame(pol_in, bg="#FFFFFF")
    tab_pat_row.grid(row=8, column=1, sticky="ew", padx=6, pady=3)
    v_tab_sel = tk.StringVar(value=cfg_cur["tabs"][0]["name"] if cfg_cur["tabs"] else "")
    v_tab_pats = tk.StringVar()

    def load_tab_pats(*_):
        tname = v_tab_sel.get()
        cur_t = next((t for t in load_config()["tabs"] if t["name"] == tname), None)
        v_tab_pats.set(", ".join(cur_t["patterns"]) if cur_t else "")

    tab_sel_cb = ttk.Combobox(
        tab_pat_row, textvariable=v_tab_sel, values=[t["name"] for t in cfg_cur["tabs"]], state="readonly", width=14
    )
    tab_sel_cb.pack(side="left", padx=(0, 4))
    ttk.Entry(tab_pat_row, textvariable=v_tab_pats).pack(side="left", fill="x", expand=True)
    tab_sel_cb.bind("<<ComboboxSelected>>", load_tab_pats)
    load_tab_pats()

    def save_tab_pat_ui():
        tname = v_tab_sel.get()
        pats = [x.strip() for x in v_tab_pats.get().split(",") if x.strip()]
        cfg_path = os.path.join(tool_dir(), CONFIG_FILE)
        user_cfg = {}
        if os.path.isfile(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    user_cfg = json.load(f)
            except (OSError, ValueError):
                user_cfg = {}
        tabs_list = user_cfg.get("tabs") or json.loads(json.dumps(CONFIG["tabs"]))
        for t in tabs_list:
            if t["name"] == tname:
                t["patterns"] = pats
                break
        user_cfg["tabs"] = tabs_list
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(user_cfg, f, indent=2)
        messagebox.showinfo("Saved", "Patterns for %s saved to %s" % (tname, cfg_path))

    def save_cfg_ui():
        ports = []
        for tok in v_risky.get().split(","):
            t = tok.strip()
            if not t:
                continue
            if t.upper() == "ANY":
                ports.append("ANY")
            elif t.isdigit() and 0 <= int(t) <= 65535:
                ports.append(int(t))
            else:
                messagebox.showerror("Invalid Port", "Invalid risky port: %r" % t)
                return
        cfg_path = os.path.join(tool_dir(), CONFIG_FILE)
        user_cfg = {}
        if os.path.isfile(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    user_cfg = json.load(f)
            except (OSError, ValueError):
                user_cfg = {}
        user_cfg["prepared_by"] = var["operator"].get().strip()
        user_cfg["risky_ports"] = ports
        user_cfg["compliance_framework"] = v_cfg_comp.get()
        v_comp_fw.set(v_cfg_comp.get())
        refresh_compliance()
        user_cfg.setdefault("policy", {}).update(
            {
                "merged_rule": v_merged.get(),
                "multi_rfc": v_multi_rfc.get(),
                "combined_row_grouping": v_combined.get(),
                "deny_rules": v_deny.get(),
                "removed_rules": v_removed.get(),
                "edited_scope": v_edited.get(),
            }
        )
        user_cfg.setdefault("asset_owner", {})["show"] = v_owner_show.get()
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(user_cfg, f, indent=2)
        messagebox.showinfo("Saved", "Settings saved to %s" % cfg_path)

    tk.Label(pol_in, text="Compliance Mode:", bg="#FFFFFF").grid(row=9, column=0, sticky="w", pady=3)
    v_cfg_comp = tk.StringVar(value=cfg_cur.get("compliance_framework", "all"))
    ttk.Combobox(pol_in, textvariable=v_cfg_comp, values=["all", "iso", "pci", "nist", "off"], state="readonly", width=18).grid(
        row=9, column=1, sticky="w", padx=6, pady=3
    )

    pbtns = tk.Frame(pol_in, bg="#FFFFFF")
    pbtns.grid(row=10, column=0, columnspan=2, sticky="w", pady=(8, 2))
    ttk.Button(pbtns, text="Save Policy Settings", style="DXC.TButton", command=save_cfg_ui).pack(side="left", padx=(0, 6))
    ttk.Button(pbtns, text="Save Tab Pattern", command=save_tab_pat_ui).pack(side="left")

    # Right card: Multi-User Auth
    auth_card, auth_in = make_card(top_cfg_row, "Access Control & Admin Login")
    auth_card.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
    auth_in.columnconfigure(1, weight=1)
    cur_auth = load_auth()
    v_auth_en = tk.BooleanVar(value=cur_auth["enabled"])
    v_auth_user = tk.StringVar()
    v_auth_pw1 = tk.StringVar()
    v_auth_pw2 = tk.StringVar()

    def toggle_auth_ui():
        try:
            save_auth_enabled(v_auth_en.get())
            messagebox.showinfo(
                "Login Protection", "Startup login protection is now %s." % ("ENABLED" if v_auth_en.get() else "DISABLED")
            )
        except AuditError as e:
            v_auth_en.set(False)
            messagebox.showerror("Login Protection", str(e))

    ttk.Checkbutton(
        auth_in, text="Enable Username & Password Login on Startup", variable=v_auth_en, command=toggle_auth_ui
    ).grid(row=0, column=0, columnspan=3, sticky="w", pady=3)
    tk.Label(auth_in, text="Username:", bg="#FFFFFF").grid(row=1, column=0, sticky="w", pady=3)
    ttk.Entry(auth_in, textvariable=v_auth_user, width=20).grid(row=1, column=1, sticky="w", padx=6, pady=3)
    tk.Label(auth_in, text="Password:", bg="#FFFFFF").grid(row=2, column=0, sticky="w", pady=3)
    ttk.Entry(auth_in, textvariable=v_auth_pw1, show="*", width=20).grid(row=2, column=1, sticky="w", padx=6, pady=3)
    tk.Label(auth_in, text="Confirm:", bg="#FFFFFF").grid(row=3, column=0, sticky="w", pady=3)
    ttk.Entry(auth_in, textvariable=v_auth_pw2, show="*", width=20).grid(row=3, column=1, sticky="w", padx=6, pady=3)

    tk.Label(auth_in, text="Authorized Users:", bg="#FFFFFF", font=("Segoe UI", 8, "bold")).grid(row=1, column=2, sticky="nw", padx=(10, 0))
    user_list = tk.Listbox(auth_in, height=4, width=22, exportselection=False)
    user_list.grid(row=2, column=2, rowspan=2, sticky="nsew", padx=(10, 0), pady=2)

    def refresh_user_list():
        user_list.delete(0, "end")
        for uname in sorted(load_auth()["users"].keys(), key=str.lower):
            user_list.insert("end", uname)

    def add_user_ui():
        p1, p2 = v_auth_pw1.get(), v_auth_pw2.get()
        if p1 != p2:
            messagebox.showerror("Mismatch", "Passwords do not match.")
            return
        try:
            add_or_update_user(v_auth_user.get(), p1)
            uname = v_auth_user.get().strip()
            v_auth_user.set("")
            v_auth_pw1.set("")
            v_auth_pw2.set("")
            refresh_user_list()
            messagebox.showinfo("User Saved", "User %r added / updated." % uname)
        except AuditError as e:
            messagebox.showerror("User Error", str(e))

    def remove_user_ui():
        sel = user_list.curselection()
        if not sel:
            messagebox.showwarning("Select User", "Select a user from the list to remove.")
            return
        uname = user_list.get(sel[0])
        try:
            remove_auth_user(uname)
            refresh_user_list()
            messagebox.showinfo("Removed", "User %r removed." % uname)
        except AuditError as e:
            messagebox.showerror("Cannot Remove", str(e))

    ubtns = tk.Frame(auth_in, bg="#FFFFFF")
    ubtns.grid(row=4, column=0, columnspan=3, sticky="w", pady=(8, 2))
    ttk.Button(ubtns, text="Add / Update User", style="Sec.TButton", command=add_user_ui).pack(side="left", padx=(0, 6))
    ttk.Button(ubtns, text="Remove Selected", command=remove_user_ui).pack(side="left")
    refresh_user_list()

    st_card, st_in = make_card(p_cfg, "System Verification & Self-Test")
    st_card.pack(fill="both", expand=True)
    st_box = tk.Text(st_in, height=10, wrap="word", state="disabled", font=("Consolas", 9), bg="#0B1930", fg="#E2E8F0", relief="flat", padx=8, pady=6)

    def run_selftest_ui():
        try:
            ok, lines = run_selftest()
        except Exception as e:
            ok, lines = False, ["Self-test error: %s" % e, traceback.format_exc()]
        st_box.configure(state="normal")
        st_box.delete("1.0", "end")
        st_box.insert("end", "\n".join(lines))
        st_box.configure(state="disabled")
        if ok:
            messagebox.showinfo("Self-Test", "SELFTEST PASSED")
        else:
            messagebox.showerror("Self-Test", "SELFTEST FAILED - see details")

    ttk.Button(st_in, text="▶  Run Built-in Self-Test", style="DXC.TButton", command=run_selftest_ui).pack(anchor="w", pady=(0, 8))
    st_box.pack(fill="both", expand=True)

    # --- Worker & Polling ---
    q = queue.Queue()

    class QueueHandler(logging.Handler):
        def emit(self, record):
            q.put(("log", record.getMessage()))

    def worker(a):
        try:
            cfg = load_config()
            setup_logging(cfg, console=False, extra_handler=QueueHandler())
            ctx, outs = run_audit(
                a["algosec"], a["rfc"] or None, a["out"], cfg, a["date"] or None,
                smax_path=a["smax"] or None, operator=a["operator"] or None,
            )
            q.put(("done", (ctx, outs)))
        except Exception as e:
            logging.getLogger("fwaudit").error("Run failed:\n%s", traceback.format_exc())
            q.put(("error", str(e)))

    def poll():
        try:
            while True:
                kind, payload = q.get_nowait()
                if kind == "log":
                    logbox.configure(state="normal")
                    logbox.insert("end", payload + "\n")
                    logbox.see("end")
                    logbox.configure(state="disabled")
                elif kind == "smax_done":
                    rc, _rdir = payload
                    smax_fetch_btn.configure(state="normal")
                    refresh_badges()
                    if rc == 0:
                        if messagebox.askyesno("SMAX Download Complete", "Finished downloading RFC sheets from SMAX.\n\nRe-run the audit now?"):
                            start_run()
                    elif rc == 2:
                        smax_session_creds["pw"] = ""
                        messagebox.showerror("SMAX Login Failed", "SMAX login failed. Check your username/password in the Audit Execution Log.")
                    else:
                        messagebox.showwarning("SMAX Fetch", "SMAX download finished with warnings (code %s). Check the Audit Execution Log." % rc)
                elif kind == "error":
                    run_btn.configure(state="normal")
                    status_pill.configure(text="ERROR", bg="#DC2626")
                    messagebox.showerror("Problem", payload)
                else:
                    ctx, outs = payload
                    run_btn.configure(state="normal")
                    last_ctx_holder["ctx"] = ctx
                    last_outputs["daily"] = outs[0]
                    last_outputs["audit"] = outs[1] if len(outs) > 1 else None
                    last_outputs["folder"] = os.path.dirname(outs[0])
                    daily_btn.configure(state="normal")
                    audit_btn.configure(state="normal")
                    html_btn.configure(state="normal")
                    cleanup_btn.configure(state="normal")
                    s = collections.Counter(ctx.verdicts[r.uid].status for r in ctx.rules)
                    kpi_vars["total"].set(str(len(ctx.rules)))
                    kpi_vars["yes"].set(str(s["YES"]))
                    kpi_vars["no"].set(str(s["NO"]))
                    kpi_vars["review"].set(str(s["REVIEW"]))
                    kpi_vars["risky"].set(str(sum(1 for r in ctx.rules if ctx.verdicts[r.uid].risky_rule)))
                    draw_compliance_bar(s["YES"], s["NO"], s["REVIEW"], s["N/A"])
                    miss_list = sorted(set(n for ru in ctx.rules for n in ru.chain if n not in ctx.sheets))
                    missing_rfcs_holder["list"] = miss_list
                    if miss_list:
                        miss_lbl_var.set("Missing RFC Sheets: %d" % len(miss_list))
                        copy_miss_btn.configure(state="normal")
                        smax_dl_btn.configure(state="normal")
                        smax_fetch_btn.configure(state="normal")
                    else:
                        miss_lbl_var.set("Missing RFC Sheets: 0 (All Present)")
                        copy_miss_btn.configure(state="disabled")
                        smax_dl_btn.configure(state="disabled")
                        smax_fetch_btn.configure(state="disabled")
                    dis_n = sum(1 for ru in ctx.rules if ru.enabled is False)
                    nodesc_n = sum(1 for ru in ctx.rules if not ru.description.strip())
                    if dis_n or nodesc_n:
                        comp_lbl_var.set(comp_lbl_var.get() + "  |  Hygiene: %d Disabled, %d Blank Desc" % (dis_n, nodesc_n))
                    for item in fw_tree.get_children():
                        fw_tree.delete(item)
                    by_fw = collections.OrderedDict((td.name, []) for td in ctx.tabs)
                    for ru in ctx.rules:
                        by_fw[ru.tab].append(ru)
                    for fname, frs in by_fw.items():
                        if frs:
                            fs = collections.Counter(ctx.verdicts[x.uid].status for x in frs)
                            fw_tree.insert(
                                "", "end",
                                values=(fname, len(frs), fs["YES"], fs["NO"], fs["REVIEW"], sum(1 for x in frs if ctx.verdicts[x.uid].risky_rule)),
                            )
                    pill_bg = "#16A34A" if ctx.status == "PASS" else ("#DC2626" if ctx.status == "ATTENTION REQUIRED" else "#D97706")
                    status_pill.configure(text=ctx.status, bg=pill_bg)
                    cached_results.clear()
                    for r in ctx.rules:
                        v = ctx.verdicts[r.uid]
                        rec = smax_record(ctx.smax, r, ctx.cfg)
                        exp_val = (rec.get("expiry") or "Permanent") if rec is not None else ""
                        exp_st = expiry_status(exp_val, ctx.report_date)
                        if isinstance(exp_val, (datetime.date, datetime.datetime)):
                            exp_val = exp_val.strftime("%d-%b-%Y")
                        if exp_st in ("EXPIRED",) or exp_st.startswith("EXPIRING SOON"):
                            exp_val = "%s [%s]" % (exp_val, exp_st)
                        cached_results.append(
                            (
                                (
                                    r.tab, r.name, ", ".join("RFC" + n for n in r.chain),
                                    r.time.strftime("%Y-%m-%d %H:%M") if r.time else r.time_text,
                                    r.src.summary(3) if r.src else "", r.dst.summary(3) if r.dst else "",
                                    r.ports.fmt() or ", ".join(r.svc_tokens), v.status,
                                    ", ".join(v.risky_ports), str(exp_val), ctx.owners[r.uid][0], v.detail,
                                ),
                                v.status,
                                r.time,
                                {"disabled": (r.enabled is False), "no_desc": (not r.description.strip()), "deny": r.is_deny, "change_type": r.change_type.lower(), "uid": r.uid},
                            )
                        )
                    avail_dates = sorted(set(x[2].strftime("%Y-%m-%d") for x in cached_results if x[2] is not None))
                    from_date_cb.configure(values=avail_dates)
                    to_date_cb.configure(values=avail_dates)
                    populate_results()
                    refresh_jobs()
                    refresh_compliance()
                    messagebox.showinfo(
                        "Audit Complete",
                        "Overall status: %s\n\nRules: %d (YES %d, NO %d, REVIEW %d)\n\n%s"
                        % (ctx.status, len(ctx.rules), s["YES"], s["NO"], s["REVIEW"], "\n".join(outs)),
                    )
        except queue.Empty:
            pass
        root.after(150, poll)

    def go():
        if not var["algosec"].get().strip():
            messagebox.showwarning("Missing input", "Choose the AlgoSec reports folder.")
            return
        a = dict((k, var[k].get().strip()) for k in var)
        a["algosec"] = [a["algosec"]]
        a["date"] = date_var.get().strip()
        try:
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump(dict((k, var[k].get().strip()) for k in var), f)
        except OSError:
            pass
        logbox.configure(state="normal")
        logbox.delete("1.0", "end")
        logbox.configure(state="disabled")
        run_btn.configure(state="disabled")
        status_pill.configure(text="RUNNING...", bg="#2563EB")
        threading.Thread(target=worker, args=(a,), daemon=True).start()

    run_btn.configure(command=go)
    select_page("dash")
    refresh_badges()
    refresh_jobs()
    root.after(150, poll)
    root.mainloop()
    return 0


# === command line ===
def main(argv=None):
    p = argparse.ArgumentParser(
        prog="fwaudit.py",
        description=(
            "Offline firewall change audit: AlgoSec reports vs RFC "
            "port sheets. No network, no AI."
        ),
    )
    p.add_argument(
        "--version", action="version", version="fwaudit %s" % VERSION
    )
    sub = p.add_subparsers(dest="cmd")
    r = sub.add_parser(
        "run",
        help=(
            "build the daily consolidated workbook and the RFC audit"
            " workbook"
        ),
    )
    r.add_argument(
        "--algosec",
        nargs="+",
        required=True,
        metavar="PATH",
        help="AlgoSec .xlsx files and/or folders",
    )
    r.add_argument(
        "--rfc",
        metavar="FOLDER",
        help="folder with the RFC port sheets (RFC_<9 digits>.xlsx)",
    )
    r.add_argument(
        "--out",
        default="output",
        metavar="FOLDER",
        help="where to write the two workbooks",
    )
    r.add_argument(
        "--smax",
        metavar="FILE_OR_FOLDER",
        help="SMAX export (.xlsx/.csv); no SMAX login is used",
    )
    r.add_argument(
        "--date",
        metavar="DD-MM-YYYY",
        help="report date (default: from the AlgoSec file names)",
    )
    r.add_argument(
        "--operator",
        metavar="USER",
        help="operator User ID written to PREPARED BY and Job Log",
    )
    r.add_argument(
        "--config",
        metavar="FILE",
        help=(
            "config JSON (default: fwaudit_config.json next to this"
            " file)"
        ),
    )
    r.add_argument(
        "--overrides",
        metavar="FILE",
        help="reviewer overrides JSON (default: review.overrides_file if present)",
    )
    r.add_argument(
        "--no-overrides",
        action="store_true",
        help="ignore reviewer overrides (pure tool verdicts)",
    )
    r.add_argument(
        "--json",
        metavar="FILE",
        help="also write every verdict, explanation and evidence as JSON",
    )
    r.add_argument(
        "--fail-on-issues",
        action="store_true",
        help="exit code 3 when any final PIR ISSUE is YES (for schedulers/CI)",
    )
    mc = sub.add_parser(
        "consolidate",
        help="merge multiple daily consolidated workbooks into one master workbook",
    )
    mc.add_argument("--in", dest="in_dir", required=True, metavar="FOLDER", help="folder of Daily_Consolidated_*.xlsx files")
    mc.add_argument("--out", default="master_output", metavar="FOLDER", help="output folder")
    mc.add_argument("--format", default="both", choices=("both", "multitab", "flat"), help="export format")
    sub.add_parser("gui", help="open the window (default)")
    sub.add_parser(
        "selftest",
        help="run a built-in check with generated sample files",
    )
    args = p.parse_args(argv)
    cmd = args.cmd or "gui"
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass
    try:
        if cmd == "run":
            cfg = load_config(args.config)
            print(
                "Firewall Audit Tool v%s (offline). Log: %s"
                % (VERSION, setup_logging(cfg))
            )
            ctx, outs = run_audit(
                args.algosec,
                args.rfc,
                args.out,
                cfg,
                args.date,
                smax_path=args.smax,
                operator=args.operator,
                overrides_path="" if args.no_overrides else args.overrides,
            )
            if args.json:
                with open(args.json, "w", encoding="utf-8") as jf:
                    json.dump(results_to_dict(ctx), jf, indent=1, default=str)
                outs.append(args.json)
            s = collections.Counter(
                ctx.verdicts[x.uid].status for x in ctx.rules
            )
            print(
                "\nRules audited : %d (YES %d | NO %d | REVIEW %d |"
                " N/A %d)"
                % (
                    len(ctx.rules),
                    s["YES"],
                    s["NO"],
                    s["REVIEW"],
                    s["N/A"],
                )
            )
            print("Overall status: %s" % ctx.status)
            for sev, m in ctx.warnings:
                print(" [%s] %s" % (sev, m))
            ost = getattr(ctx, "override_stats", {}) or {}
            if any(ost.get(k) for k in ("applied", "pending", "stale")):
                print(
                    "Overrides     : %d applied | %d pending approval |"
                    " %d not applied (rule changed)"
                    % (len(ost.get("applied", [])), len(ost.get("pending", [])),
                       len(ost.get("stale", [])))
                )
            for o in outs:
                print("Written: %s" % o)
            if args.fail_on_issues and s["YES"]:
                return 3
            return 0
        if cmd == "consolidate":
            stats, outs = merge_consolidated_folder(args.in_dir, args.out, fmt=args.format)
            print("Merged %d file(s), %d tab(s), %d total rules." % (stats["files_read"], stats["tabs"], stats["total_rules"]))
            for o in outs:
                print("Written: %s" % o)
            return 0
        if cmd == "gui":
            return run_gui()
        if cmd == "selftest":
            setup_logging(console=False)
            ok, lines = run_selftest()
            print("\n".join(lines))
            return 0 if ok else 1
        return 2
    except AuditError as e:
        print("\nProblem with the input: %s" % e)
        return 2
    except PermissionError as e:
        print(
            "\nCannot read or write a file (is it open in Excel?): %s"
            % e
        )
        return 2
    except KeyboardInterrupt:
        print("\nStopped.")
        return 1
    except Exception:
        logging.getLogger("fwaudit").error(
            "Unexpected error:\n%s", traceback.format_exc()
        )
        print(
            "\nUnexpected error. Details are in fwaudit.log next to"
            " this file."
        )
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())