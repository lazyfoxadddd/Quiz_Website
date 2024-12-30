from app import app, db, User, Quiz, Question
from werkzeug.security import generate_password_hash

def init_db_with_sample_data():
    with app.app_context():
        db.create_all()

        # Add a sample teacher
        teacher = User(username='teacher1', password=generate_password_hash('password'), user_type='teacher')
        db.session.add(teacher)
        db.session.commit()

        # Add a sample quiz
        quiz = Quiz(title='Sample Quiz', teacher_id=teacher.id)
        db.session.add(quiz)
        db.session.commit()

        # Add questions to the quiz
        questions = [
            ('What is 2 + 2?', '4'),
            ('What is 5 x 3?', '15'),
            ('What is 10 divided by 2?', '5'),
            ('What is the square root of 16?', '4'),
            ('What is 3 squared?', '9')
        ]

        for question_text, answer in questions:
            question = Question(quiz_id=quiz.id, question_text=question_text, correct_answer=answer)
            db.session.add(question)

        db.session.commit()

if __name__ == '__main__':
    init_db_with_sample_data()
    print("Database initialized with sample data.")