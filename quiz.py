from data.quiz_questions import questions
from banner import banner_heading, banner_summary
import random

def load_quiz_questions(level):
    # Filter questions from Python list based on difficulty level.
    result = []  
    for q in questions:
        if q["level"] == level:
            result.append(q)
    return result

def ask_questions(questions, num_questions=5):
    # Ask the user questions and track score.
    score = 0
    random.shuffle(questions)
    selected_questions = questions[:num_questions]

    for idx, q in enumerate(selected_questions, start=1):
        print(f"\nQuestion {idx}: {q['q']}")
        for key, value in q['options'].items():
            print(f"    {key}: {value}")
    
        while True:
            answer = input("Your answer (a/b/c/d): ").strip().lower()
            if answer in ["a", "b", "c", "d"]:
                break
            else:
                print("Invalid choice! Please enter a, b, c, or d.")

        if answer == q['answer']:
            print("Correct!")
            score += 1
        else:
            print(f"Wrong! The correct answer was {q['answer']}.")
            print(f"Explanation: {q['explain']}")
    
    return score, len(selected_questions)

def start_quiz():
    # Main entry for running the quiz.
    banner_heading("Cybersecurity Awareness Quiz")

    print("Select Difficulty Level:")
    print("1) Beginner\n2) Intermediate\n3) Advanced")

    level_map = {
        "1": "beginner", 
        "2": "intermediate", 
        "3": "advanced"
    }

    while True:
        level_choice = input("Enter your choice (1/2/3): ").strip()
        if level_choice in level_map:
            level = level_map[level_choice]
            break
        else:
            print("Invalid choice! Please select 1, 2, or 3.")

    questions = load_quiz_questions(level)
    if not questions:
        print("No questions available for this level.")
        return
    
    score, total = ask_questions(questions, num_questions=5)

    banner_summary("Quiz Summary")
    print(f"Score: {score}/{total}")
    percentage = (score / total) * 100
    print(f"Percentage: {percentage:.2f}%")
    print(f"\nThank you for participating in the quiz on the {level.capitalize()} level!\n")