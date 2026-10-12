import { SafeHabitsLesson } from '../types';

export const SAFE_HABITS_LESSONS: SafeHabitsLesson[] = [
  {
    id: 'lesson-digital-arrest',
    title: 'Spotting "Digital Arrest" Extortion',
    nativeTitle: '"डिजिटल अरेस्ट" फर्जीवाड़े को पहचानें',
    category: 'calls',
    durationMin: 2,
    summary:
      'Scammers impersonate CBI, Customs, or Police officers over Skype/WhatsApp video calls claiming you are "arrested" due to an illegal package or money laundering.',
    takeaways: [
      'Indian law enforcement and courts NEVER conduct trials or arrests via Skype or video calls.',
      'There is NO legal concept of "Digital Arrest" under the Bharatiya Nagarik Suraksha Sanhita (BNSS) or CrPC.',
      'Never transfer money into any "Supreme Court" or "RBI Verification" bank account.',
    ],
    quiz: {
      id: 'quiz-da-1',
      question:
        'A caller claiming to be a CBI officer orders you to stay on a WhatsApp video call for 4 hours for a "Digital Arrest" interrogation. What should you do?',
      options: [
        {
          text: 'Comply with the instructions and do not tell your family.',
          isCorrect: false,
          explanation:
            'Incorrect. Scammers demand secrecy to isolate victims and prevent family intervention.',
        },
        {
          text: 'Immediately disconnect the call, block the number, and alert your family.',
          isCorrect: true,
          explanation:
            'Correct! Indian Police or CBI never conduct arrests on video calls. Disconnect immediately.',
        },
        {
          text: 'Transfer money to the "RBI security deposit" account to clear your name.',
          isCorrect: false,
          explanation:
            'Incorrect. RBI never maintains individual citizen verification deposit accounts.',
        },
      ],
    },
  },
  {
    id: 'lesson-upi-rule',
    title: 'The Golden UPI Rule: PIN is Only for Sending',
    nativeTitle: 'गोल्डन UPI नियम: पिन केवल पैसे भेजने के लिए होता है',
    category: 'payments',
    durationMin: 2,
    summary:
      'The #1 financial cyber fraud in India is the "Cashback / Lottery Collect Request". Scammers tell you to enter your UPI PIN to "receive" funds into your account.',
    takeaways: [
      'You NEVER need to enter your UPI PIN to receive money, cashback, or refunds.',
      'Scanning a QR code is strictly to pay someone, NEVER to receive funds.',
      'Entering your UPI PIN always authorizes a DEBIT from your bank account.',
    ],
    quiz: {
      id: 'quiz-upi-1',
      question:
        'You receive a message saying: "You won ₹25,000 lottery cashback. Click here, scan QR, and enter UPI PIN to receive funds." What is true?',
      options: [
        {
          text: 'Entering your UPI PIN will deposit ₹25,000 into your account.',
          isCorrect: false,
          explanation:
            'Incorrect! Entering a UPI PIN will deduct money from your account, not credit it.',
        },
        {
          text: 'This is a scam. Receiving money never requires entering a UPI PIN.',
          isCorrect: true,
          explanation:
            'Correct! A UPI PIN is strictly an authorization for debiting money from your bank account.',
        },
        {
          text: 'You should share the OTP with customer care to speed up payment.',
          isCorrect: false,
          explanation:
            'Incorrect! Never share OTPs under any circumstances.',
        },
      ],
    },
  },
  {
    id: 'lesson-electricity',
    title: 'Electricity Bill Power Cut SMS Phishing',
    nativeTitle: 'बिजली बिल कटने का फर्जी SMS स्कैम',
    category: 'messages',
    durationMin: 2,
    summary:
      'A panic-inducing SMS warns that your electricity power supply will be cut tonight at 9:30 PM due to an unpaid bill, asking you to call an unofficial mobile number.',
    takeaways: [
      'Electricity distribution companies (discoms) send official SMS from verified alphanumeric sender IDs (e.g., AD-MSEDCL, TA-BESCOM), not personal 10-digit mobile numbers.',
      'Fraudsters ask you to install AnyDesk or TeamViewer to make a nominal ₹10 payment, allowing them to steal your credentials.',
      'Always check bill status directly on your official discom consumer portal or state electricity app.',
    ],
    quiz: {
      id: 'quiz-elec-1',
      question:
        'You receive an SMS from a standard 10-digit mobile number stating: "Your electricity will be disconnected tonight. Call officer at 98765xxxxx". What should you do?',
      options: [
        {
          text: 'Call the mobile number and download the app the officer asks for.',
          isCorrect: false,
          explanation:
            'Incorrect. Calling the number connects you directly to the scammer.',
        },
        {
          text: 'Ignore the phone number in SMS; verify bill status on your electricity provider’s official app/portal.',
          isCorrect: true,
          explanation:
            'Correct! State discoms never send bill alerts from personal 10-digit numbers.',
        },
        {
          text: 'Forward the message to all your society WhatsApp groups.',
          isCorrect: false,
          explanation:
            'Incorrect. Forwarding spreads panic without independent verification.',
        },
      ],
    },
  },
  {
    id: 'lesson-voice-cloning',
    title: 'Deepfake Audio & Cloned Voice Scams',
    nativeTitle: 'डीपफेक ऑडियो और वॉयस क्लोनिंग स्कैम',
    category: 'media',
    durationMin: 3,
    summary:
      'Using generative AI voice cloning, scammers clone the voice of your child, parent, or friend using short audio from social media, then call claiming an emergency or accident.',
    takeaways: [
      'Do not panic if you hear a family member’s voice crying or asking for urgent funds from an unknown number.',
      'Hang up immediately and dial your family member on their KNOWN phone number.',
      'Establish a secret "Family Safe Word" to verify distress calls.',
    ],
    quiz: {
      id: 'quiz-voice-1',
      question:
        'You receive a call from an unknown number with your friend’s voice urgently begging for ₹50,000 bail money because they were arrested. What is your best first step?',
      options: [
        {
          text: 'Send the money immediately via UPI to the provided unknown number.',
          isCorrect: false,
          explanation:
            'Incorrect. Once transferred to a scammer mule account, funds are difficult to recover.',
        },
        {
          text: 'Hang up and dial your friend directly on their regular, known mobile number.',
          isCorrect: true,
          explanation:
            'Correct! Always verify emergency claims by calling the person directly on their known phone.',
        },
        {
          text: 'Post on social media asking if your friend was arrested.',
          isCorrect: false,
          explanation:
            'Incorrect. A direct phone call is the fastest and safest verification.',
        },
      ],
    },
  },
];
